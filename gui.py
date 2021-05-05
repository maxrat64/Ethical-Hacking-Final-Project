from tkinter import *
import webbrowser


def display(d, l):

    # repopulate display when a new CPE is selected
    def select(evt):
        new_cpe = str(listbox.get(listbox.curselection()))
        new_entry = cpes[new_cpe]
        header.config(text=new_cpe)
        new_ips = "IP:port pairs running service: \n"
        for ip in new_entry["ips"][:-1]:
            new_ips = new_ips + ip + "\n"
        new_ips = new_ips + new_entry["ips"][-1]
        ips.config(text=new_ips)
        new_desc = ""
        new_desc = new_desc + "Number of vulnerabilities: " + \
            str(new_entry["results"]["n_vulns"]) + "\n"
        new_desc = new_desc + "Highest CVSS severity score: " + \
            str(new_entry["results"]["max"]) + "\n"
        new_desc = new_desc + "Average CVSS severity score: " + \
            str(round(new_entry["results"]["avg"], 1)) + "\n"
        desc.config(text=new_desc)
        url_button = Button(master=frame, text="Learn More", command=open_url)
        url_button.pack()

    def open_url():
        cpe = header.cget("text")
        url = cpes[cpe]["results"]["url"]
        webbrowser.open(url)

    def populate():
        listbox.delete(0, END)
        cpe = {}
        with l:
            # parse input
            for ip in d.keys():
                ip_block = d[ip]
                for port in ip_block.keys():
                    port_block = ip_block[port]
                    for spec in port_block.keys():
                        result_dict = port_block[spec]
                        if spec in cpes.keys():
                            cpes[spec]["ips"].append(str(ip) + ":" + str(port))
                        else:
                            cpes[spec] = {}
                            cpes[spec]["ips"] = [str(ip) + ":" + str(port)]
                            cpes[spec]["results"] = result_dict

        # populate listbox
        for cpe in cpes.keys():
            listbox.insert(END, str(cpe))
        window.after(5000, populate)

    # create root window
    window = Tk()
    window.title("Vulnerama")
    window.geometry("1200x500")
    scrollbar = Scrollbar(window)
    scrollbar.pack(side=LEFT, fill=Y)
    listbox = Listbox(window, yscrollcommand=scrollbar.set,
                      width=50, font=("Consolas", 12))

    cpes = {}
    populate()
    listbox.pack(side=LEFT, fill=BOTH)
    scrollbar.config(command=listbox.yview)

    # initialize frame to display default entry
    frame = Frame(master=window)
    frame.pack()
    cpes_keys = cpes.keys()
    value_iterator = iter(cpes_keys)
    header_text = "Vulnerama"
    header = Label(master=frame, text=str(header_text), font=("Consolas", 20))
    header.pack()

    ips_text = "Select a CPE from the list"
    ips = Label(master=frame, text=ips_text,
                wraplength=500, font=("Consolas", 15))
    ips.pack()

    desc_text = "<Waiting for selection>"
    desc = Label(master=frame, text=desc_text,
                 wraplength=500, font=("Consolas", 15))
    desc.pack()

    listbox.bind('<<ListboxSelect>>', select)

    window.mainloop()
