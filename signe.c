#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

//gcc -o signe signe.c -lssl -lcrypto
int main()
{
    printf("I - Inicio del programa \n\n");
    int err;
    int sig_len;
    unsigned char sig_buf[4096];
    static char publicCert[] = "public-key.pem";
    static char privateCert[] = "private-key.pem";
    static char x509cert[] = "cert.pem";
    static char file[] = "data.txt";
    static char *data;

    EVP_MD_CTX *md_ctx;
    EVP_PKEY *pkey;
    FILE *fp;
    X509 *x509;

    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL)
        printf("Errorsas0\n");
    EVP_MD_CTX_free(md_ctx);

    ERR_load_crypto_strings();

    /* Read data */
    long lSize;
    char *buffer;

    fp = fopen(file, "rb");
    if (!fp)
        perror(file), exit(1);

    fseek(fp, 0L, SEEK_END);
    lSize = ftell(fp);
    rewind(fp);

    buffer = calloc(1, lSize + 1);
    if (!buffer)
        fclose(fp), fputs("memory alloc fails", stderr), exit(1);

    /* copy the file into the buffer */
    if (1 != fread(buffer, lSize, 1, fp))
        fclose(fp), free(buffer), fputs("entire read fails", stderr), exit(1);

    /* do your work here, buffer is a string contains the whole text */
    data = buffer;
    fclose(fp);
    printf("Data: \t%s\n\n", data);

    /* Read private key */
    printf("I - Read Private Key\n");
    fp = fopen(privateCert, "r");
    if (fp == NULL)
    {
        printf("E - Read Private Key - Empty \n");
        exit(1);
    }

    pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (pkey == NULL)
    {
        ERR_print_errors_fp(stderr);
        printf("E - Read Private Key - ERR_print_errors_fp \n");
        exit(1);
    }
    printf("S - Read Private Key\n");

    /* Do the signature */
    printf("I - Do signature\n");
    EVP_SignInit(md_ctx, EVP_sha1());
    EVP_SignUpdate(md_ctx, data, strlen(data));
    sig_len = sizeof(sig_buf);
    err = EVP_SignFinal(md_ctx, sig_buf, &sig_len, pkey);

    if (err != 1)
    {
        printf("E - Do signature - Error in signature \n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    EVP_PKEY_free(pkey);
    printf("S - Do Signature \n");
    printf("%s\n", sig_buf);

    /*Write signed file*/
    fp = fopen("signed", "w+");
    int results = fputs(sig_buf, fp);
    if (results == EOF) {
        printf("E - Writing signed file");
    }
    fclose(fp);

    /* Read public key */
    printf("I - Read Public Key\n");
    fp = fopen(publicCert, "r");
    if (fp == NULL)
    {
        printf("E - FP Read Public Key - Empty \n");
        exit(1);
    }
    printf("S - Read public key \n");

    printf("I - Read cert\n");
    X509 *cert = X509_new();
    BIO *bio_cert = BIO_new_file(x509cert, "rb");
    x509 = PEM_read_bio_X509(bio_cert, &cert, NULL, NULL);
    pkey = X509_get_pubkey(x509);
    printf("S - Read cert\n");

    /* Verify the signature */
    printf("I - Verify Signatre\n");
    EVP_VerifyInit(md_ctx, EVP_sha1());
    EVP_VerifyUpdate(md_ctx, data, strlen((char *)data));
    err = EVP_VerifyFinal(md_ctx, sig_buf, sig_len, pkey);
    EVP_PKEY_free(pkey);

    if (err != 1)
    {
        ERR_print_errors_fp(stderr);
        printf("E - Bad Signature  \n");
        exit(1);
    }
    printf("S - Signature Verified Ok.\n");

    printf("\nI -Fin del programa \n");
    free(buffer);
    return (0);
}