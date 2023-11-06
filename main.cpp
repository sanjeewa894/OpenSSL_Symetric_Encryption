#include <QCoreApplication>
#include <QDebug>
#include "symetric_encyprtion.h"

const QString inputFile = "input.txt";
const QString encryptedFile = "encrypted.enc";
const QString decryptedFile = "decrypted.txt";


void checkSymetric() {
  SymetricEncryption enc;
  enc.generateKey();

  enc.encryptFile (inputFile, encryptedFile);

  /*****************************Decript*************************************/
  enc.decryptFile (encryptedFile, decryptedFile);

}

int main (int argc, char *argv[]) {
  QCoreApplication a (argc, argv);

  checkSymetric();

  return 0;
}
