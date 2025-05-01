from pymongo import MongoClient

client = MongoClient("mongodb://10.245.0.197:27017/")
db = client["monitor"]
collection = db["mirror"]

# insert
def mongodb_insert(cluster, mirror_pod_name, ifname):
    doc = {
            "cluster": cluster,
            "mirror_pod_name": mirror_pod_name,
            "ifname": ifname
        }
    print(f"Inserting for {cluster}: {doc}")
    try:
        collection.insert_one(doc)
    except Exception as e:
        print(f"Error insert to MongoDB: {e}")
        return None
    
    return "Insert Success"

# updaet
def mongodb_update(cluster, mirror_pod_name, ifname):
    # 構建更新條件 (匹配的條件)
    query = {
        "cluster": cluster,
        "mirror_pod_name": mirror_pod_name,
        "ifname": ifname,
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