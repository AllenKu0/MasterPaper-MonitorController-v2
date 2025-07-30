from pymongo import MongoClient
import kubernetes as k

client = MongoClient("mongodb://10.244.0.174:27017/")
db = client["monitor"]
collection = db["upf"]

def init(clusters):
    for cluster in clusters:
        data = k.get_pod_info_by_lable(cluster, "app=free5gc-upf") 
        pod_names = data["pod_name"]
        pod_ip = data["pod_ip"]
        enable = data["enable"]
        pod_mac = data["pod_mac"]
        result = mongodb_insert(cluster, pod_names, pod_ip, pod_mac, enable)
        print(f"Result: {result}")
        
    return collection

def mongodb_insert(cluster, pod_name, pod_ip, pod_mac, enable):
    # 去除空白以避免重複資料格式問題
    cluster = cluster.strip()
    pod_name = pod_name.strip()
    pod_ip = pod_ip.strip()
    pod_mac = pod_mac.strip()
    enable = enable.strip()

    # 查詢是否已存在相同的 cluster + pod_name
    existing = collection.find_one({"cluster": cluster, "pod_name": pod_name})
    if existing:
        print(f"[MongoDB] Duplicate entry found for cluster={cluster}, pod_name={pod_name}. Skipping insert.")
        return "Duplicate Entry Skipped"

    # 準備文件
    doc = {
        "cluster": cluster,
        "pod_name": pod_name,
        "pod_ip": pod_ip,
        "pod_mac": pod_mac,
        "enable": enable
    }

    print(f"Inserting for {cluster}: {doc}")
    try:
        collection.insert_one(doc)
    except Exception as e:
        print(f"Error insert to MongoDB: {e}")
        return None

    return "Insert Success"
# updaet
def mongodb_update(cluster, pod_name, enable):
    # 構建更新條件 (匹配的條件)
    query = {
        "cluster": cluster,
        "pod_name": pod_name
    }

    # 構建更新的內容
    update = {
        "$set": {
            "enable": enable
        }
    }

    print(f"Updating for {cluster}: {query} with {update}")

    try:
        # 使用 upsert=True，如果資料不存在則插入新資料
        result = collection.update_one(query, update, upsert=True)
        return result
    except Exception as e:
        print(f"Error updating MongoDB: {e}")
        return None
    
# Get
def mongodb_get(query, fields):
    """
    從 MongoDB 獲取指定欄位的資料。

    :param collection: MongoDB 中的集合 (collection)。
    :param query: 查詢條件 (dict)。
    :param fields: 要返回的欄位列表 (list of str)，例如 ["pod_name", "pod_ip"]。
                   如果為空，則返回所有欄位。
    :return: 匹配條件的資料列表 (list of dict)。
    """
    # 如果 fields 是空的，則返回所有欄位
    projection = {field: 1 for field in fields} if fields else None
    
    # 查詢 MongoDB
    documents = collection.find(query, projection)
    # 返回查詢結果的列表
    return list(documents)

# remove
def mongodb_remove(query):
    """
    從 MongoDB 中刪除符合條件的文件。

    :param query: 查詢條件 (dict)，例如 {"cluster": "cluster-a", "mirror_pod_name": "pod-a"}
    :return: 被刪除的筆數 (int)
    """
    print(f"Removing documents with query: {query}")
    try:
        result = collection.delete_many(query)
        print(f"Deleted {result.deleted_count} documents.")
        return result.deleted_count
    except Exception as e:
        print(f"Error deleting from MongoDB: {e}")
        return None
    
def mongodb_clear_all():
    """
    清空整個 upf collection 的所有資料。
    使用前請確認不需要備份資料。
    """
    try:
        result = collection.delete_many({})
        print(f"Cleared all documents. Deleted count: {result.deleted_count}")
        return result.deleted_count
    except Exception as e:
        print(f"Error clearing MongoDB collection: {e}")
        return None    