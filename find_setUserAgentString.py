from androguard.misc import AnalyzeAPK
from os import listdir
from os.path import isfile, join

apk_path = 'APKs'
apks = [f for f in listdir(apk_path) if isfile(join(apk_path, f))]

# clean files
log = open('log.txt', 'w+')
log.close()
spoofing_apks_file = open('spoofing_apks.txt', 'w+')
spoofing_apks_file.close()

# process
for i, apk in enumerate(apks):
    log_strings = []
    log_string = "{}/{}".format(i, len(apks))
    print(log_string)
    log_strings.append(log_string + "\n")

    spoofed = False
    a, d, dx = AnalyzeAPK(join(apk_path, apk))
    for c in dx.get_classes():
        for meth in c.get_methods():
            if meth.name == 'setUserAgentString':
                log_string = "Class: {} \t APK: {}".format(c.name, apk)
                print(log_string)
                log_strings.append(log_string + "\n")
                for _, call, _ in meth.get_xref_from():
                    log_string = "  called by -> {} -- {}".format(call.class_name, call.name)
                    print(log_string)
                    log_strings.append(log_string + "\n")
                    # check if class belongs to google
                    if not "google" in call.class_name:
                        spoofed = True
                continue
    # write files
    log = open('log.txt', 'a+')
    log.writelines(log_strings)
    log.close()
    if spoofed:
        spoofing_apks_file = open('spoofing_apks.txt', 'a+')
        spoofing_apks_file.writelines(log_strings)
        spoofing_apks_file.close()
