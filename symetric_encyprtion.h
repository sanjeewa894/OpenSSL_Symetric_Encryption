/**
 * @copyright Copyright (c) by Versatile Ag.
 *            All rights reserved.
 *  Author: skumara@versatile-ag.com
*/
#ifndef SYMETRIC_ENCYPRTION_H
#define SYMETRIC_ENCYPRTION_H


#include <QFile>
#include <QObject>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

class SymetricEncryption : public QObject {
    Q_OBJECT
  public:
    explicit SymetricEncryption (QObject *parent = nullptr);
      ~SymetricEncryption();

    void encryptFile (const QString &inputFilePath, const QString &outputFilePath);
    void decryptFile (const QString &inputFilePath, const QString &outputFilePath);
    void generateKey();
    QString getErrorFromEVPHandler();


private:
    int keySize = 2048;
    void runDecryption (QFile &inFile, QByteArray &outData);
    void runEncryption (QFile &inFile, QByteArray &outData);
    void getEncryptData (EVP_CIPHER_CTX *ctx, QFile &inFile, QByteArray &outData);
    void getDecryptData (EVP_CIPHER_CTX *ctx, QFile &inFile, QByteArray &outData);

    unsigned char *symetricKey=nullptr;

};

#endif // SYMETRIC_ENCYPRTION_H
