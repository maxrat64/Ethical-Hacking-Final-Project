from tkinter import *

# tutorial - https://realpython.com/python-gui-tkinter/#controlling-layout-with-geometry-managers


def display(cves):
    # create root window
    window = Tk()
    window.title("<TITLE HERE>")
    window.geometry("900x500")
    scrollbar = Scrollbar(window)
    scrollbar.pack(side=LEFT, fill=Y)

    # populate listbox
    listbox = Listbox(window, yscrollcommand=scrollbar.set, width=50)
    for cve in cves:
        listbox.insert(END, str(cve["id"]))
    listbox.pack(side=LEFT, fill=BOTH)
    scrollbar.config(command=listbox.yview)

    # initialize frame to display selected entry
    frame = Frame(master=window)
    frame.pack()
    cur_id = Label(master=frame, text=cves[0]["id"])
    cur_id.pack()
    cur_desc = Label(master=frame, text=cves[0]["description"], wraplength=500)
    cur_desc.pack()
    refs_text = ""
    for ref in cves[0]["references"][:-1]:
        refs_text = refs_text + ref + "\n"
    refs_text = refs_text + cves[0]["references"][-1]
    cur_ref = Label(master=frame, text=refs_text, wraplength=500)
    cur_ref.pack()
    if cves[0]["impact"] != None:
        cur_imp = Label(master=frame, text=cves[0]["impact"], wraplength=500)
    else:
        cur_imp = Label(master=frame, text="N/A")
    cur_imp.pack()

    # repopulate display when a new CVE is selected
    def select(evt):
        cve = str(listbox.get(listbox.curselection()))
        for i in range(len(cves)):
            if cves[i]["id"] == cve:
                break
        new_id = cve
        new_desc = cves[i]["description"]
        new_refs_text = ""
        for ref in cves[i]["references"][:-1]:
            new_refs_text = new_refs_text + ref + "\n"
        new_refs_text = new_refs_text + cves[i]["references"][-1]
        if cves[i]["impact"] != None:
            new_imp = cves[i]["impact"]
        else:
            new_imp = "N/A"
        cur_id.config(text=new_id)
        cur_desc.config(text=new_desc)
        cur_ref.config(text=new_refs_text)
        cur_imp.config(text=new_imp)
            
    listbox.bind('<<ListboxSelect>>', select)

    window.mainloop()