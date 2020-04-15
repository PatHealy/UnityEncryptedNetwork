using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Numerics;

using UnityEngine;
using UnityEngine.Networking;
using System.Security.Cryptography;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

public class NetworkManager : MonoBehaviour
{
    public GameObject[] parents;
    public GameObject[] children;

    string getPublicKeyURL = "http://127.0.0.1:5000/publicKey";
    string getKeysURL = "http://127.0.0.1:5000/privateKeys";
    string establishConnectionURL = "http://127.0.0.1:5000/attemptStart";
    string sendParentsURL = "http://127.0.0.1:5000/com";
    string testEncryptionURL = "http://127.0.0.1:5000/testEncryption";

    string publicServerRSA;
    
    RSACryptoServiceProvider clientRSA; //Decrypts based on client private key
    RSACryptoServiceProvider serverRSA; //Encrypts based on server public key

    bool started = false;

    public int playerNum;

    public enum EncryptionMode {None, AES, DES, DES3, Blowfish, RSA};
    public EncryptionMode encryptionMode = EncryptionMode.None;

    // Start is called before the first frame update
    void Start()
    {
        clientRSA = new RSACryptoServiceProvider(2048);
        var pubKey = clientRSA.ExportParameters(false);
        //converting the public key into a string representation
        string pubKeyString;
        {
            //we need some buffer
            var sw = new System.IO.StringWriter();
            //we need a serializer
            var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
            //serialize the key into the stream
            xs.Serialize(sw, pubKey);
            //get the string from the stream
            pubKeyString = sw.ToString();
        }
        StartCoroutine(EstablishConnectionToHost());
    }

    RSACryptoServiceProvider ImportPublicKey(RSAKeySet keys) {
        RSAParameters rsaParams = new RSAParameters();
        rsaParams.Modulus = keys.n;
        rsaParams.Exponent = keys.e;

        RSACryptoServiceProvider csp = new RSACryptoServiceProvider();
        csp.ImportParameters(rsaParams);
        return csp;
    }

    RSACryptoServiceProvider ImportPrivateKey(RSAKeySetPrivate keys) {
        RSAParameters rsaParams = new RSAParameters();
        rsaParams.Modulus = keys.n;
        rsaParams.Exponent = keys.e;
        rsaParams.D = keys.d;
        rsaParams.P = keys.p;
        rsaParams.Q = keys.q;

        RSACryptoServiceProvider csp = new RSACryptoServiceProvider();
        csp.ImportParameters(rsaParams);
        return csp;
    }

    IEnumerator EstablishConnectionToHost() {
        // Get the server public keys
        using (UnityWebRequest webRequest = UnityWebRequest.Get(getPublicKeyURL)) {
            yield return webRequest.SendWebRequest();
            if (webRequest.isNetworkError) {
                Debug.Log("Connection failed");
            } else {
                //serverRSA = ImportPublicKey(webRequest.downloadHandler.text);
                //serverRSA = ImportPublicKey(JsonUtility.FromJson<RSAKeySet>(webRequest.downloadHandler.text));
                serverRSA = ImportPrivateKey(JsonUtility.FromJson<RSAKeySetPrivate>(webRequest.downloadHandler.text));
            }
        }

        //Encrypt my public keys and send them to server, include set of parent objects
        string testEncryptString = "Test message";
        byte[] encryptedTest = serverRSA.Encrypt(Encoding.UTF8.GetBytes(testEncryptString), true);
        //byte[] decryptedTest = serverRSA.Decrypt(encryptedTest, true);
        //Debug.Log(Encoding.UTF8.GetString(decryptedTest));

        WWWForm form1 = new WWWForm();
        EncryptedData d = new EncryptedData();
        d.data = encryptedTest;
        form1.AddField("test", JsonUtility.ToJson(d));

        using (UnityWebRequest webRequest = UnityWebRequest.Post(testEncryptionURL, form1)) {

            yield return webRequest.SendWebRequest();

            if (webRequest.isNetworkError) {
                Debug.Log("Connection failed");
            } else {
                if (webRequest.downloadHandler.text == "go") {
                    started = true;
                }
                Debug.Log(webRequest.downloadHandler.text);
            }
        }

        yield return new WaitForFixedUpdate();
        Debug.Break();

        //Process response, which includes set of keys for ciphers (i.e. create those ciphers)



        //Wait for all players to connect
        /*WWWForm form = new WWWForm();
        form.AddField("PlayerID", playerNum);

        while (!started) {
            using (UnityWebRequest webRequest = UnityWebRequest.Post(establishConnectionURL, form)) {
            
                yield return webRequest.SendWebRequest();

                if (webRequest.isNetworkError) {
                    Debug.Log("Connection failed");
                } else {
                    if (webRequest.downloadHandler.text == "go") {
                        started = true;
                    }
                    Debug.Log(webRequest.downloadHandler.text);
                }
            }
        }*/

    }

    string Encrypt(string plaintext) {
        return plaintext;
    }

    string Decrypt(string ciphertext) {
        return ciphertext;
    }

    IEnumerator Exchange() {

        ObjectInfoSet toSend = new ObjectInfoSet();
        toSend.data = new List<ObjectInfo>();
        for (int i = 0; i < parents.Length; i++) {
            toSend.data.Add(new ObjectInfo(parents[i]));
        }

        WWWForm form = new WWWForm();
        form.AddField("data", Encrypt(JsonUtility.ToJson(toSend)));

        using (UnityWebRequest webRequest = UnityWebRequest.Post(sendParentsURL, form)) {
            yield return webRequest.SendWebRequest();

            if (webRequest.isNetworkError) {
                Debug.Log("Connection failed");
            } else {
                ObjectInfoSet received = JsonUtility.FromJson<ObjectInfoSet>(Decrypt(webRequest.downloadHandler.text));
                foreach (ObjectInfo o in received.data) {
                    foreach (GameObject g in children) {
                        if (g.name == o.name) {
                            Debug.Log("Set " + g.name);
                            g.transform.position = o.position;
                            g.transform.rotation = UnityEngine.Quaternion.Euler(o.rotation);
                        }
                    }
                }
            }
        }
    }

    void FixedUpdate()
    {
        if (started) {
            StartCoroutine(Exchange());
        }
    }

    private class ObjectInfoSet {
        public List<ObjectInfo> data;
    }

    private class KeySet {
        string AES_key;
    }

    private class RSAKeySet {
        public byte[] n;
        public byte[] e;
    }

    private class RSAKeySetPrivate {
        public byte[] n;
        public byte[] e;
        public byte[] d;
        public byte[] p;
        public byte[] q;
        public byte[] u;
    }

    private class EncryptedData {
        public byte[] data;
    }
}
