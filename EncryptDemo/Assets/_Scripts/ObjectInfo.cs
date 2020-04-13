using System.Collections;
using System.Collections.Generic;
using UnityEngine;

[System.Serializable]
public class ObjectInfo
{
    public string name;
    public Vector3 position;
    public Vector3 rotation;

    public ObjectInfo(string n, Vector3 p, Quaternion r) {
        name = n;
        position = p;
        rotation = r.eulerAngles;
    }

    public ObjectInfo(GameObject g) {
        name = g.name;
        position = g.transform.position;
        rotation = g.transform.rotation.eulerAngles;
    }
}
