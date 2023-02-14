from censys.search import CensysCertificates
import datetime
import csv


c = CensysCertificates()

now = datetime.datetime.now()

fields_to_retrieve = [
    "parsed.subject_dn",
    "parsed.names",
    "parsed.subject.common_name",
    "parsed.fingerprint_sha256",
    "parsed.validity.start",
    "parsed.validity.end",
]


certificate_list = []
header = ["SHA256 fingerprint", "Validity Start", "Validity End"]


def create_csv():
    with open('censys.csv', 'w', encoding='UTF8', newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        for certificate in certificate_list:
            writer.writerow(certificate)


def censys_certificates():
    for page in c.search("parsed.names: censys.io and tags: trusted", fields_to_retrieve):
        subject_dn = page["parsed.subject_dn"]
        names = page["parsed.names"]
        validity_start = page["parsed.validity.start"]
        validity_end = page["parsed.validity.end"]
        sha256 = page["parsed.fingerprint_sha256"]
        
        censys_domain_flag = 0

        if "censys.io".lower() in subject_dn.lower():
            censys_domain_flag = 1
        else:
            for name in names:
                if "censys.io".lower() in name.lower():
                    censys_domain_flag = 1
                    break
        
        validity_end_dt = datetime.datetime.strptime(validity_end, "%Y-%m-%dT%H:%M:%SZ")


        if censys_domain_flag and validity_end_dt >= now:
            certificate_list.append([sha256, str(validity_start), str(validity_end)])



if __name__ == "__main__":
    censys_certificates()
    create_csv()