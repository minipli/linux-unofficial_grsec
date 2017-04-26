#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/scatterlist.h>
#include <linux/crypto.h>
#include <linux/gracl.h>
#include <crypto/algapi.h>
#include <crypto/hash.h>

#if !defined(CONFIG_CRYPTO) || defined(CONFIG_CRYPTO_MODULE) || !defined(CONFIG_CRYPTO_SHA256) || defined(CONFIG_CRYPTO_SHA256_MODULE)
#error "crypto and sha256 must be built into the kernel"
#endif

int
chkpw(struct gr_arg *entry, unsigned char *salt, unsigned char *sum)
{
	struct crypto_ahash *tfm;
	struct ahash_request *req;
	struct scatterlist sg[2];
	unsigned char temp_sum[GR_SHA_LEN];
	unsigned long *tmpsumptr = (unsigned long *)temp_sum;
	unsigned long *sumptr = (unsigned long *)sum;
	int retval = 1;

	tfm = crypto_alloc_ahash("sha256", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm))
		goto out_wipe;

	sg_init_table(sg, 2);
	sg_set_buf(&sg[0], salt, GR_SALT_LEN);
	sg_set_buf(&sg[1], entry->pw, strlen((const char *)entry->pw));

	req = ahash_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		crypto_free_ahash(tfm);
		goto out_wipe;
	}

	ahash_request_set_callback(req, 0, NULL, NULL);
	ahash_request_set_crypt(req, sg, temp_sum, GR_SALT_LEN + strlen((const char *)entry->pw));

	if (crypto_ahash_digest(req))
		goto out_free;

	if (!crypto_memneq(sumptr, tmpsumptr, GR_SHA_LEN))
		retval = 0;

out_free:
	ahash_request_free(req);
	crypto_free_ahash(tfm);
out_wipe:
	memset(entry->pw, 0, GR_PW_LEN);

	return retval;
}
