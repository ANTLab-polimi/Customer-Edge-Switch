import yaml
import inotify.adapters
import time
import threading


policies_list = []

#check if PolicyDB has been modified
def mod_detecter():
    while True:
        i = inotify.adapters.Inotify()
        i.add_watch("policiesDB.yaml")

        for event in i.event_gen(yield_nones=False):
            (_, type_names, path, filename) = event

            if "IN_CLOSE_WRITE" in event[1]: #type_names is a list
                print("[!] POLICYDB MODIFIED")
                mod_manager()

            #log:
            #print("PATH=[{}] FILENAME=[{}] EVENT_TYPES={}".format(path, filename, type_names))


#find out specific modifications per policy
#[!] TOADD: ip management when auth \wo ip
def mod_manager():
    global policies_list
    tmp = policies_list
    getPolicies()
    
    found = False

    for policy_tmp in tmp:

        for policy in policies_list:
            if policy.get("serviceName") == policy_tmp.get("serviceName"):
                found = True
                
                if policy.get("ip") != policy_tmp.get("ip"):
                    print("[!] IP_MODIFICATIONS")
                    print("[!] Editing policies IP...")
                    editIPPolicies(policy_tmp.get("ip"), policy.get("ip"), policy.get("port"))
        
                if policy.get("port") != policy_tmp.get("port"):
                    print("[!] PORT_MODIFICATIONS")
                    print("[!] Editing policies Port...")
                    editPortPolicies(policy_tmp.get("ip"), policy_tmp.get("port"))

                if policy.get("protocol") != policy_tmp.get("protocol"):
                    print("[!] PROTOCOL_MODIFICATIONS")
                    
                #UE checks (add or del)
                for ue in policy.get("allowed_users"):
                    if ue not in policy_tmp.get("allowed_users"):
                        print("[!] UE_MODIFICATIONS_ADD")
                        addEntries(ue_ip, policy.get("ip"), policy.get("port")) #[!] how to handle ue_ip \w auth different from ip?
                for ue in policy_tmp.get("allowed_users"):
                    if ue not in policy.get("allowed_users"):
                        print("[!] UE_MODIFICATIONS_DEL")
                        delUE(ue_ip, policy.get("ip")) #[!] how to handle ue_ip \w auth different from ip?

                if policy.get("tee") != policy_tmp.get("tee"):
                    print("[!] TEE_MODIFICATIONS")
                    
                if policy.get("fs_encr") != policy_tmp.get("fs_encr"):
                    print("[!] FS_ENCR_MODIFICATIONS")
                    
                if policy.get("net_encr") != policy_tmp.get("net_encr"):
                    print("[!] NET_ENCR_MODIFICATIONS")
                    
                if policy.get("sec_boot") != policy_tmp.get("sec_boot"):
                    print("[!] SEC_BOOT_MODIFICATIONS")
                    
                break

            if not found:
                print("[!] Service not found")   
                print("[!] Deleting service policies...")
                delPolicies(policy.get("ip"))
    
    print("[!] New policies_list: ")
    print(policies_list)


#del policies when service not found
def delPolicies(ip):
    for te in sh.Table_entry("my_ingress.ipv4_exact").read():
        if te.match["hdr.ipv4.srcAddr"] == ip:
            te.delete()


#edit service ip 
def editIPPolicies(old_ip, new_ip, port):
    for te in sh.TableEntry("my_ingress.ipv4_exact").read():
        if te.match["hdr.ipv4.srcAddr"] == old_ip:
            src_addr = te.match["hdr.ipv4.src_addr"]
            te.delete()
            te = sh.TableEntry('my_ingress.ipv4_exact')(action='my_ingress.ipv4_forward')
            te.match["hdr.ipv4.srcAddr"] = src_addr
            te.match["hdr.ipv4.dstAddr"] = new_ip
            te.action["port"] = port
            te.insert()


#edit service port
def editPortPolicies(ip, new_port):
    for te in sh.TableEntry("my_ingress.ipv4_exact").read():
        if te.match["hdr.ipv4.srcAddr"] == ip:
            src_addr = te.match["hdr.ipv4.src_addr"]
            te.delete()
            te = sh.TableEntry('my_ingress.ipv4_exact')(action='my_ingress.ipv4_forward')
            te.match["hdr.ipv4.srcAddr"] = src_addr
            te.match["hdr.ipv4.dstAddr"] = ip
            te.action["port"] = new_port
            te.insert()


#delete a policy (old service, user not allowed anymore)
def delUE(ue_ip, service_ip):
    for te in table_entry["my_ingress.ipv4_exact"].read():
        if te.match["hdr.ipv4.srcAddr"] == ue_ip and te.match["hdr.ipv4.dstAddr"] == service_ip:
            te.delete()


#add a new entry
def addEntry(ip_src, ip_dst, port):
    te = sh.TableEntry('my_ingress.ipv4_exact')(action='my_ingress.ipv4_forward')
    te.match["hdr.ipv4.srcAddr"] = ip_src
    te.match["hdr.ipv4.dstAddr"] = ip_dst
    te.action["port"] = port
    te.insert()
    print("[!] New entry added")


#getPolicies from policyDB     
def getPolicies():
    global policies_list
    stream = open("policiesDB.yaml", 'r')
    policies_list = yaml.safe_load(stream)


def main():
    global policies_list
    getPolicies()
    while True:
        stream = open("policiesDB.yaml", 'r')
        policies_list = yaml.safe_load(stream)
        print("policy_list opened")
        #print(policies_list)
        print("\n\n\n\n\n\n")
        
        #how to get a specific policy
        #for policy in policies_list:
        #    if policy.get("ip") == "10.0.2.2" and policy.get("port") == 48 and policy.get("protocol") == "TCP":
        #        for user in policy.get("allowed_users"):
        #            print(user.get("method") + ": " + user.get("user"))

        time.sleep(10)


detector = threading.Thread(target = mod_detecter)
detector.start()
main()