#include "ac17_gcm256.h"


using namespace std;


int main(){
    AC17 ac17;
    ac17.setup("C:\\Users\\WanThinnn\\Downloads");
    ac17.generateSecretKey("public_key.key", "master_key.key", "a b c d", "private_key.key");
    ac17.encrypt("public_key.key", "plaintext.txt", "((a or b) and (c or d))", "ciphertext.txt");
    ac17.decrypt("public_key.key", "private_key.key", "ciphertext.txt", "recovertext.txt");
    return 0;   
}