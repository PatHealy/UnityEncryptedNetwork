using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using UnityEngine.Networking;

public class NetworkManager : MonoBehaviour
{
    public GameObject[] parents;
    public GameObject[] children;

    string establishConnectionURL = "http://127.0.0.1:5000/attemptStart";
    string sendParentsURL = "http://127.0.0.1:5000/com";

    bool started = false;

    public int playerNum;

    // Start is called before the first frame update
    void Start()
    {
        StartCoroutine(EstablishConnectionToHost());
    }

    IEnumerator EstablishConnectionToHost() {
        WWWForm form = new WWWForm();
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
        }

    }

    IEnumerator GetChildren() {
        yield return null;
    }

    IEnumerator Exchange() {

        ObjectInfoSet toSend = new ObjectInfoSet();
        toSend.data = new List<ObjectInfo>();
        for (int i = 0; i < parents.Length; i++) {
            toSend.data.Add(new ObjectInfo(parents[i]));
        }

        WWWForm form = new WWWForm();
        form.AddField("data", JsonUtility.ToJson(toSend));

        using (UnityWebRequest webRequest = UnityWebRequest.Post(sendParentsURL, form)) {
            yield return webRequest.SendWebRequest();

            if (webRequest.isNetworkError) {
                Debug.Log("Connection failed");
            } else {
                ObjectInfoSet received = JsonUtility.FromJson<ObjectInfoSet>(webRequest.downloadHandler.text);
                foreach (ObjectInfo o in received.data) {
                    foreach (GameObject g in children) {
                        if (g.name == o.name) {
                            Debug.Log("Set " + g.name);
                            g.transform.position = o.position;
                            g.transform.rotation = Quaternion.Euler(o.rotation);
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
}
