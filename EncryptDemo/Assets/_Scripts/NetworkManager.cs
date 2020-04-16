using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Numerics;
using System;

using UnityEngine;
using UnityEngine.Networking;
using System.Security.Cryptography;

public class NetworkManager : MonoBehaviour {
    public string encryptionMethod = "RSA";
    public GameObject[] parents;
    public GameObject[] children;

    string getPublicKeyURL = "http://127.0.0.1:5000/publicKey";
    string getBigPublicKeyURL = "http://127.0.0.1:5000/largePublicKey";
    string getKeysURL = "http://127.0.0.1:5000/privateKeys";
    string establishConnectionURL = "http://127.0.0.1:5000/attemptStart";
    string sendParentsURL = "http://127.0.0.1:5000/com";
    string testEncryptionURL = "http://127.0.0.1:5000/testEncryption";

    RSACryptoServiceProvider clientRSA; //Decrypts based on client private key
    RSACryptoServiceProvider serverRSA; //Encrypts based on server public key
    RSACryptoServiceProvider serverBigRSA;
    RSAKeySet clientPublicKeys;
    PrivateKey privateKeys;

    int RSAChunkSize = 128;

    bool started = false;

    public int playerNum;

    public enum EncryptionMode { None, AES, DES, DES3, Blowfish, RSA };
    public EncryptionMode encryptionMode = EncryptionMode.None;

    // Start is called before the first frame update
    void Start() {
        clientRSA = new RSACryptoServiceProvider(2048);
        var pubKey = clientRSA.ExportParameters(false);

        clientPublicKeys = new RSAKeySet();
        clientPublicKeys.n = pubKey.Modulus;
        clientPublicKeys.e = pubKey.Exponent;

        ObjectInfoSet toSend = new ObjectInfoSet();
        toSend.data = new List<ObjectInfo>();
        for (int i = 0; i < parents.Length; i++) {
            toSend.data.Add(new ObjectInfo(parents[i]));
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
                serverRSA = ImportPublicKey(JsonUtility.FromJson<RSAKeySet>(webRequest.downloadHandler.text));
            }
        }

        //Large public key (for bigger, more secure stuff)
        using (UnityWebRequest webRequest = UnityWebRequest.Get(getBigPublicKeyURL)) {
            yield return webRequest.SendWebRequest();
            if (webRequest.isNetworkError) {
                Debug.Log("Connection failed");
            } else {
                serverBigRSA = ImportPublicKey(JsonUtility.FromJson<RSAKeySet>(webRequest.downloadHandler.text));
            }
        }

        //Encrypt my public keys and send them to server
        WWWForm form1 = new WWWForm();
        Handshake d = new Handshake();
        d.n = clientPublicKeys.n;
        d.e = clientPublicKeys.e;
        d.playerNum = playerNum;
        d.method = encryptionMethod;

        string handshakeJson = JsonUtility.ToJson(d);
        byte[] encryptedHandshake = serverBigRSA.Encrypt(Encoding.UTF8.GetBytes(handshakeJson), true);

        EncryptedData e = new EncryptedData();
        e.data = encryptedHandshake;

        form1.AddField("data", JsonUtility.ToJson(e));

        using (UnityWebRequest webRequest = UnityWebRequest.Post(getKeysURL, form1)) {
            yield return webRequest.SendWebRequest();
            if (webRequest.isNetworkError) {
                Debug.Log("Connection failed");
            } else {
                string decryptedString = Encoding.UTF8.GetString(clientRSA.Decrypt(JsonUtility.FromJson<EncryptedData>(webRequest.downloadHandler.text).data, true));
                Debug.Log(decryptedString);
                privateKeys = JsonUtility.FromJson<PrivateKey>(decryptedString);
            }
        }

        StartCoroutine(Exchange());

        //Process response, which includes set of keys for ciphers (i.e. create those ciphers)
        //TODO

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

    ToSendData Encrypt(string plaintext) {
        ToSendData toSend = new ToSendData();
        toSend.playerNum = playerNum;
        switch (encryptionMethod) {
            case "RSA":
                toSend.data = serverRSA.Encrypt(Encoding.UTF8.GetBytes(plaintext), true);
                break;
            case "AES":
                toSend.data = Encoding.UTF8.GetBytes(plaintext);
                break;
            case "DES":
                toSend.data = Encoding.UTF8.GetBytes(plaintext);
                break;
            case "DES3":
                toSend.data = Encoding.UTF8.GetBytes(plaintext);
                break;
            case "Blowfish":
                toSend.data = Encoding.UTF8.GetBytes(plaintext);
                break;
            default:
                toSend.data = Encoding.UTF8.GetBytes(plaintext);
                break;
        }
        return toSend;
    }

    string Decrypt(byte[] ciphertext) {
        switch (encryptionMethod) {
            case "RSA":
                return Encoding.UTF8.GetString(clientRSA.Decrypt(ciphertext, true));
                break;
            case "AES":
                return Encoding.UTF8.GetString(ciphertext);
                break;
            case "DES":
                return Encoding.UTF8.GetString(ciphertext);
                break;
            case "DES3":
                return Encoding.UTF8.GetString(ciphertext);
                break;
            case "Blowfish":
                return Encoding.UTF8.GetString(ciphertext);
                break;
            default:
                return Encoding.UTF8.GetString(ciphertext);
                break;
        }
        return Encoding.UTF8.GetString(ciphertext);
    }

    string[] Chunk(string plaintext, int chunkSize) {
        string[] chunks = new string[(int)Math.Ceiling((double)plaintext.Length/chunkSize)];
        string temp = "" + plaintext;
        for (int i = 0; i < chunks.Length - 1; i++) {
            chunks[i] = temp.Substring(0, chunkSize);
            temp = temp.Substring(chunkSize);
        }
        chunks[chunks.Length] = temp;
        return chunks;
    }

    string UnChunk(string[] chunked) {
        string unchunked = "";
        for (int i = 0; i < chunked.Length; i++) {
            unchunked += chunked[i];
        }
        return unchunked;
    }

    byte[][] RSAEncrypt(string plaintext, RSACryptoServiceProvider rsa) {
        string[] chunked = Chunk(plaintext, RSAChunkSize);
        byte[][] encrypted = new byte[chunked.Length][];

        for (int i = 0; i < chunked.Length; i++) {

        }

        return null;
    }

    IEnumerator Exchange() {

        ObjectInfoSet toSend = new ObjectInfoSet();
        toSend.data = new List<ObjectInfo>();
        for (int i = 0; i < parents.Length; i++) {
            toSend.data.Add(new ObjectInfo(parents[i]));
        }

        WWWForm form = new WWWForm();
        form.AddField("data", JsonUtility.ToJson(Encrypt(JsonUtility.ToJson(toSend))));

        using (UnityWebRequest webRequest = UnityWebRequest.Post(sendParentsURL, form)) {
            yield return webRequest.SendWebRequest();

            if (webRequest.isNetworkError) {
                Debug.Log("Connection failed");
            } else {
                EncryptedData d = JsonUtility.FromJson<EncryptedData>(webRequest.downloadHandler.text);
                ObjectInfoSet received = JsonUtility.FromJson<ObjectInfoSet>(Decrypt(d.data));
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

    void FixedUpdate() {
        if (started) {
            StartCoroutine(Exchange());
        }
    }

    private class ObjectInfoSet {
        public List<ObjectInfo> data;
    }

    private class PrivateKey {
        public byte[] key;
        public byte[] iv;
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

    private class ToSendData {
        public byte[] data;
        public int playerNum;
    }

    private class Handshake{
        public int playerNum;
        public string method;
        public byte[] n;
        public byte[] e;
    }
}
