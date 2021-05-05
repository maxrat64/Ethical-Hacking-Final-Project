from tkinter import *
import webbrowser


def display(d, l):
    # create root window
    window = Tk()
    window.title("Vulnerama")
    window.geometry("1200x500")
    scrollbar = Scrollbar(window)
    scrollbar.pack(side=LEFT, fill=Y)
    listbox = Listbox(window, yscrollcommand=scrollbar.set, width=50)

    def populate():
        listbox.delete(0, END)
        print("populating data")
        with l:
            # parse input
            for ip in d.keys():
                ip_block = d[ip]
                for port in ip_block.keys():
                    port_block = ip_block[port]
                    for spec in port_block.keys():
                        result_dict = port_block[spec]
                        if spec in cpes.keys():
                            host_port = str(ip) + ":" + str(port)
                            if host_port not in cpes[spec]["ips"]:
                                cpes[spec]["ips"].append(str(ip) + ":" + str(port))
                        else:
                            cpes[spec] = {}
                            cpes[spec]["ips"] = [str(ip) + ":" + str(port)]
                            cpes[spec]["results"] = result_dict

        # populate listbox
        for cpe in cpes.keys():
            listbox.insert(END, str(cpe))

        window.after(5000, populate)

    cpes = {}
    populate()
    listbox.pack(side=LEFT, fill=BOTH)
    scrollbar.config(command=listbox.yview)

    # initialize frame to display default entry
    frame = Frame(master=window)
    frame.pack()
    cpes_keys = cpes.keys()
    value_iterator = iter(cpes_keys)
    # default_cpe = next(value_iterator)
    default_cpe = "blah"
    # default_entry = cpes[default_cpe]
    cur_id = Label(master=frame, text=str(default_cpe))
    cur_id.pack()
    ips_text = "IP:port pairs running service: \n"
    # for ip in default_entry["ips"][:-1]:
    #    ips_text = ips_text + ip + "\n"
    # ips_text = ips_text + default_entry["ips"][-1]
    cur_ips = Label(master=frame, text=ips_text, wraplength=500)
    cur_ips.pack()
    desc_text = ""
    # desc_text = desc_text + "Number of vulnerabilities: " + \
    #    str(default_entry["results"]["n_vulns"]) + "\n"
    # desc_text = desc_text + "Highest CVSS severity score: " + \
    #    str(default_entry["results"]["max"]) + "\n"
    # desc_text = desc_text + "Average CVSS severity score: " + \
    #    str(round(default_entry["results"]["avg"], 1)) + "\n"
    # desc_text = desc_text + "Learn more: " + default_entry["results"]["url"]
    cur_desc = Label(master=frame, text=desc_text, wraplength=500)
    cur_desc.pack()

    # repopulate display when a new CPE is selected
    def select(evt):
        new_cpe = str(listbox.get(listbox.curselection()))
        new_entry = cpes[new_cpe]
        cur_id.config(text=new_cpe)
        new_ips = "IP:port pairs running service: \n"
        for ip in new_entry["ips"][:-1]:
            new_ips = new_ips + ip + "\n"
        new_ips = new_ips + new_entry["ips"][-1]
        cur_ips.config(text=new_ips)
        new_desc = ""
        new_desc = new_desc + "Number of vulnerabilities: " + \
            str(new_entry["results"]["n_vulns"]) + "\n"
        new_desc = new_desc + "Highest CVSS severity score: " + \
            str(new_entry["results"]["max"]) + "\n"
        new_desc = new_desc + "Average CVSS severity score: " + \
            str(round(new_entry["results"]["avg"], 1)) + "\n"
        # new_desc = new_desc + "Learn more: " + new_entry["results"]["url"]
        cur_desc.config(text=new_desc)

    def open_url():
        cpe = cur_id.cget("text")
        url = cpes[cpe]["results"]["url"]
        webbrowser.open(url)

    listbox.bind('<<ListboxSelect>>', select)

    url_button = Button(master=frame, text="Learn More", command=open_url)
    url_button.pack()

    window.mainloop()
