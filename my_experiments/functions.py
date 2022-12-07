# def update_super_log_file(self,client,bucket_name):
#     check_bucket_name(bucket_name,True)
#     found=client.bucket_exists(bucket_name)
#     if not found:
#         print("No bucket is found")
#     else:
#         print("Bucket {} exists".format(bucket_name))
#         response = self._execute("GET", bucket_name, query_params={"owner": ""},)
#         bucket_owner=response.data.decode()
#         bucket_policy=client.get_bucket_policy(bucket_name)
#         bucket_notification=client.get_bucket_notification(bucket_name)
#         bucket_encryption=client.get_bucket_encryption(bucket_name,config)
#         response = self._execute("GET", bucket_name, query_params={"url": ""},)
#         bucket_url=response.data.decode()
#         response = self._execute("GET", bucket_name, query_params={"size": ""},)
#         bucket_size=response.data.decode()
#     data=[bucket_name,bucket_owner,bucket_policy,bucket_notification,bucket_encryption,bucket_url,bucket_size]
#     with open('super_log_file.csv', 'w', encoding='UTF8', newline='') as f:
#     writer=csv.writer(f)
#     writer.writerow(data)
    
# def update_sub_log_file(self,bucket):
#     check_bucket_name(bucket_name,True)
#     found=client.bucket_exists(bucket_name)
#     if not found:
#         print("No bucket is found")
#     else:
#         print("Bucket {} exists".format(bucket_name))
#         response = self._execute("GET", bucket_name, query_params={"owner": ""},)
#         bucket_owner=response.data.decode()
#         bucket_policy=client.get_bucket_policy(bucket_name)
#         bucket_notification=client.get_bucket_notification(bucket_name)
#         bucket_encryption=client.get_bucket_encryption(bucket_name,config)
#         response = self._execute("GET", bucket_name, query_params={"url": ""},)
#         bucket_url=response.data.decode()
#         response = self._execute("GET", bucket_name, query_params={"size": ""},)
#         bucket_size=response.data.decode()
#     data=[bucket_name,bucket_owner,bucket_policy,bucket_notification,bucket_encryption,bucket_url,bucket_size]
#     with open('super_log_file.csv', 'w', encoding='UTF8', newline='') as f:
#     writer = csv.writer(f)
#     writer.writerow(data)

def update_sub_log_file(self,bucket_name):
    with open('sub_log_file.csv', 'w', encoding='UTF8', newline='') as f:
        writer=csv.writer(f)
    response = self._execute("GET", bucket_name, query_params={"owner": ""},)
    bucket_owner=response.data.decode()
    bucket_policy=self.get_bucket_policy(bucket_name)
    bucket_notification=self.get_bucket_notification(bucket_name)
    bucket_encryption=self.get_bucket_encryption(bucket_name)
    response = self._execute("GET",bucket_name,query_params={"url": ""},)
    bucket_url=response.data.decode()
    response = self._execute("GET", bucket_name, query_params={"size": ""},)
    bucket_size=response.data.decode()
    data=[bucket_name,bucket_owner,bucket_policy,bucket_notification,bucket_encryption,bucket_url,bucket_size]
    writer.writerow(data)