using UnityEditor;
using UnityEngine;

public class SnapToGround : MonoBehaviour {
    [MenuItem("Custom/Snap To Ground %g")]
    public static void Ground() {
        foreach (var transform in Selection.transforms) {
            Vector3 bottomPos = transform.position;
            foreach(Collider c in transform.gameObject.GetComponentsInChildren<Collider>()) {
                if (c.bounds.min.y < bottomPos.y) {
                    bottomPos = c.bounds.min;
                }
            }

            var hits = Physics.RaycastAll(bottomPos + Vector3.up, Vector3.down, 10f);
            float minDistance = float.MaxValue;
            Vector3 hitPoint = transform.position;

            foreach (var hit in hits) {
                if (hit.collider.gameObject == transform.gameObject)
                    continue;

                if (hit.distance < minDistance) {
                    minDistance = hit.distance;
                    hitPoint = hit.point;
                }
            }

            transform.position = hitPoint - (bottomPos - transform.position);
        }
    }

}

