#include "symetric_encyprtion.h"
#include <QDebug>

SymetricEncryption::SymetricEncryption (QObject *parent)
  : QObject{parent} {

}

SymetricEncryption::~SymetricEncryption(){
  if(symetricKey)
    free (symetricKey);
}

/**
 * @brief SymetricEncryption::generateKey -- generate symetric key
 */
void SymetricEncryption::generateKey() {
  symetricKey = (unsigned char *) (malloc (keySize));
  if (RAND_bytes (symetricKey, sizeof (symetricKey)) == 0) {
    /* OpenSSL reports a failure, act accordingly */
    return;
  }

#ifdef WRITE_KEY_TOFILE
  //write to file
  QFile writeTo ("saved_key.key");
  if (writeTo.open (QIODevice::WriteOnly) && sizeof (key) > 0) {
    writeTo.write ((char *) (lkey), keySize);
    writeTo.close();
  }
#endif
}

/**
 * @brief SymetricEncryption::encryptFile -- encrypt input file and write to output file
 * @param inputFile -- input file path
 * @param outputFile -- output file path
 */
void SymetricEncryption::encryptFile (const QString &inputFilePath, const QString &outputFilePath) {
  QFile inFile (inputFilePath);
  QFile outFile (outputFilePath);
  QByteArray outData;

  if (!inFile.open (QIODevice::ReadOnly)) {
    qDebug() << "Failed to open encrypted input file" << __LINE__;
    return;
  }
  if (!outFile.open (QIODevice::WriteOnly)) {
    qDebug() << "Failed to open output file for decrypt" << __LINE__;
    return;
  }

  if(symetricKey == nullptr){
    qDebug()<<"Key is empty!";
    return;
  }

  runEncryption (inFile, outData);
  outFile.write (outData);
  inFile.close();
  outFile.close();
  qDebug() << "Encryption successfully completed.";

}

/**
 * @brief SymetricEncryption::runEncryptionProcess -- Create and initialize encryption handler and call encypt data
 * @param inFile -- input file
 * @param outData -- array to save encrypted data
 */
void SymetricEncryption::runEncryption (QFile &inFile,  QByteArray &outData) {
  // Create and initialise the context
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (ctx == nullptr) {
    qDebug() << "EVP_CIPHER_CTX_new failed. " << getErrorFromEVPHandler() << __LINE__;
    return;
  }

  unsigned char iv[EVP_MAX_IV_LENGTH];
  // Initialise the encryption operation. 1 is for encription
  if (EVP_CipherInit_ex (ctx, EVP_aes_256_cbc(), nullptr, symetricKey, iv, 1) != 1) {
    EVP_CIPHER_CTX_free (ctx);
    qDebug() << "EVP_CipherInit_ex failed. " << getErrorFromEVPHandler() << __LINE__;
    return;
  }

  getEncryptData (ctx, inFile, outData);
  EVP_CIPHER_CTX_free (ctx); //clean up

}

/**
 * @brief SymetricEncryption::getEncryptedData -- Encrypt data in keyblock size and save in array
 * @param ctx -- EVP context handler
 * @param inFile -- input file
 * @param outData -- array to save data
 */
void SymetricEncryption::getEncryptData (EVP_CIPHER_CTX *ctx, QFile &inFile, QByteArray &outData) {
  int outLength = 0, total_out = 0;
  QByteArray inData;
  outData.reserve (static_cast<int> (inFile.size()) + EVP_CIPHER_CTX_block_size (ctx));
  /*
  * Provide the message to be encrypted, and obtain the encrypted output.
  * EVP_CipherUpdate can be called multiple times if necessary. Here called for keysize data
  */
  while ((inData = inFile.read (keySize)).size() > 0) {
    if (EVP_CipherUpdate (ctx, reinterpret_cast<unsigned char *> (outData.data()), &outLength, reinterpret_cast<const unsigned char *> (inData.constData()), inData.size()) != 1) {
      qDebug() << "EVP_CipherUpdate failed. " << getErrorFromEVPHandler() << __LINE__;
      return;
    }
    total_out += outLength;
  }

  outData.resize (total_out);
  /*
  * Finalise the encryption. Further ciphertext bytes may be written at
  * this stage.
  */
  if (EVP_CipherFinal (ctx, reinterpret_cast<unsigned char *> (outData.data()) + total_out, &outLength) != 1) {
    qDebug() << "EVP_CipherFinal failed. " << getErrorFromEVPHandler() << __LINE__;
    return;
  }
  total_out += outLength;
  outData.resize (total_out);
}

/**
 * @brief SymetricEncryption::decryptFile -- decrypt the encrypted file
 * @param inputFile -- input file path
 * @param outputFile -- output file path
 */
void SymetricEncryption::decryptFile (const QString &inputFilePath, const QString &outputFilePath) {
  QFile inFile (inputFilePath);
  QFile outFile (outputFilePath);
  QByteArray outData;

  if (!inFile.open (QIODevice::ReadOnly)) {
    qDebug() << "Failed to open encrypted input file" << __LINE__;
    return;
  }
  if (!outFile.open (QIODevice::WriteOnly)) {
    qDebug() << "Failed to open output file for decrypt" << __LINE__;
    return;
  }

  if(symetricKey == nullptr){
    qDebug()<<"Key is empty!";
    return;
  }

  runDecryption (inFile, outData);
  outFile.write (outData);
  inFile.close();
  outFile.close();

  qDebug() << "Decryption successfully completed.";
}

/**
 * @brief SymetricEncryption::runDecryptionProcess -- create and initialize the EVP handler and call decrypt process
 * @param inFile -- input file
 * @param outData -- array to save decrypted data
 */
void SymetricEncryption::runDecryption (QFile &inFile,  QByteArray &outData) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (ctx == nullptr) {
    qDebug() << "EVP_CIPHER_CTX_new failed. " << getErrorFromEVPHandler() << __LINE__;
    return;
  }
  unsigned char iv[EVP_MAX_IV_LENGTH];

  // Initialise the encryption operation. 0 is for decription
  if (EVP_CipherInit_ex (ctx, EVP_aes_256_cbc(), nullptr, symetricKey, iv, 0) == 0) {
    EVP_CIPHER_CTX_free (ctx);
    qDebug() << "EVP_CipherInit_ex failed. " << getErrorFromEVPHandler() << __LINE__;
    return;
  }

  outData.reserve (static_cast<int> (inFile.size()) + EVP_CIPHER_CTX_block_size (ctx));
  getDecryptData (ctx, inFile, outData);
  EVP_CIPHER_CTX_free (ctx); //clean up

}

/**
 * @brief SymetricEncryption::getDecryptData -- decrypt the input data in keysize block and save in the array
 * @param ctx -- EVP context
 * @param inFile -- input file
 * @param outData -- array to save the decrypted data
 */
void SymetricEncryption::getDecryptData (EVP_CIPHER_CTX *ctx, QFile &inFile, QByteArray &outData) {
  int outLength = 0, total_out = 0;
  QByteArray inData;

  /*
  * Provide the message to be decrypted, and obtain the plain output.
  * EVP_CipherUpdate can be called multiple times if necessary. it is called in keysize data
  */
  while ((inData = inFile.read (keySize)).size() > 0) {
    if (EVP_CipherUpdate (ctx, reinterpret_cast<unsigned char *> (outData.data()), &outLength, reinterpret_cast<const unsigned char *> (inData.constData()), inData.size()) != 1) {
      qDebug() << "EVP_CipherUpdate failed. " << getErrorFromEVPHandler() << __LINE__;
      return;
    }
    total_out += outLength;
  }
  outData.resize (outLength);

  // Finalise the decryption. Further plain bytes may be written at this stage.
  if (EVP_CipherFinal (ctx, reinterpret_cast<unsigned char *> (outData.data()) + total_out, &outLength) != 1) {
    qDebug() << "EVP_CipherFinal failed. " << getErrorFromEVPHandler() << __LINE__;
    return;
  }
  total_out += outLength;
  outData.resize (total_out);
}

/**
 * @brief AsymetricEncryption::getErrorFromEVP -- get all the error messsages when executing EVP functions
 * @return -- Error message received from EVP
 */
QString SymetricEncryption::getErrorFromEVPHandler() {
  QString errorMsg;
  int line = 0, flags = 0;
  uint64_t e = 0;
  const char *file = nullptr, *func = nullptr, *data = nullptr;
  while ((e = ERR_get_error_all (&file, &line, &func, &data, &flags)) != 0) {
    errorMsg += QString (ERR_lib_error_string (e)) + ":"
                + ERR_reason_error_string (e) + ":" + file
                + ':' + func + ':' + QString::number (line) + "\n";
  }
  return errorMsg;
}
