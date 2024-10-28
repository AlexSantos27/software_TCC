import os 
import pyshark
import psutil
import lxml
import pandas as pd
import tkinter as tk #
import asyncio
import time

from tkinter import ttk
from tkinter import filedialog
from tkinter import scrolledtext
from lxml import etree
from tkinter import scrolledtext
from threading import Thread
from tkinter import PhotoImage


Arquivo_SCD_path = None
Dataframe_capturado = None
Projeto_verificado = None
find_GOOSE = None
find_coluna0_text1 = None
find_coluna1_text1 = None
find_coluna0_text2 = None
find_coluna1_text2 = None
find_coluna0_text3 = None
find_coluna1_text3 = None
find_coluna0_text4 = None
find_coluna1_text4 = None
find_coluna0_text5 = None
find_coluna1_text5 = None
find_coluna0_text6 = None
find_coluna1_text6 = None
find_coluna0_text7 = None
find_coluna1_text7 = None
find_coluna0_text8 = None
find_coluna1_text8 = None
find_coluna0_text9 = None
find_coluna1_text9 = None
find_coluna0_text10 = None
find_coluna1_text10 = None

capturing = False

def Lista_redes():
  interfaces = psutil.net_if_addrs()
  interface_name_lista = []
  for interface_name, addresses in interfaces.items():
      interface_name_lista.append(interface_name)
  redes["values"] = interface_name_lista

def Arquivo_SCD():
  global Arquivo_SCD_path
  janela_carregar = tk.Tk()
  janela_carregar.withdraw()
  SCD_path = filedialog.askopenfilename()
  janela_carregar.destroy()
  Arquivo_SCD_path = str(SCD_path)

def capture_packets(text_widget):
    global Dataframe_capturado
    global capturing
    asyncio.set_event_loop(asyncio.new_event_loop())
    Interface_escolhida= redes.get()
    capture = pyshark.LiveCapture(interface=Interface_escolhida, display_filter='goose')
    ether=0 
    VLAN=-1 
    GOOSE=0 
    GCB_IED2 = {}
    GCB_IED2['gocbref'] = ['MAC-Addres','APPID','goID','datSet','VLAN_ID','VLAN_PRIORITY','confRev','timeAllowedtoLive','numDatSetEntries']
    df_0 = pd.DataFrame()
    Dataframe_capturado = df_0
    for packet in capture.sniff_continuously():
        goose_control_block = devices.get()+goose.get()+'/'+dataset.get()
        goose_control_block=goose_control_block.replace('.','$GO$')
        if not capturing:  
            break
        lista_chave1= []
        count=0
        for i in packet.layers:
          if i.layer_name == 'eth':
              ether = count
          elif i.layer_name == 'goose':
              GOOSE = count   
          elif i.layer_name == 'vlan':
              VLAN = count   
          count+=1
        lista_chave1.append(packet[GOOSE].gocbref)
        MAC_ADDRESS = packet[ether].dst
        MAC_ADDRESS = MAC_ADDRESS.replace(':','-')
        MAC_ADDRESS = MAC_ADDRESS.upper()
        lista_chave1.append(MAC_ADDRESS)
        lista_chave1.append(packet[GOOSE].appid)
        lista_chave1.append(packet[GOOSE].goid)
        lista_chave1.append(packet[GOOSE].datset)
        if VLAN != -1:
          if len(packet[VLAN].ID) == 1:
            lista_chave1.append('00'+packet[VLAN].ID)
          elif len(packet[VLAN].ID) == 2:
            lista_chave1.append('0'+packet[VLAN].ID)
          elif len(packet[VLAN].ID) == 3:
            lista_chave1.append(packet[VLAN].ID)
          lista_chave1.append(packet[VLAN].Priority)
        else:
          lista_chave1.append('')
          lista_chave1.append('')
        lista_chave1.append(packet[GOOSE].confrev)
        lista_chave1.append(packet[GOOSE].timeallowedtoLive)
        lista_chave1.append(packet[GOOSE].numdatsetentries)
        GCB_IED2[lista_chave1[0]] = lista_chave1[1:len(lista_chave1)+1]
        df2 = pd.DataFrame(GCB_IED2)
        coluna_fixa = df2.columns[0]
        df_0 = df2
        Dataframe_capturado = df_0
        coluna_fixa = df_0.columns[0]
        for coluna in df_0.columns[1:]:
          df_combinado = pd.DataFrame({coluna_fixa: df_0[coluna_fixa], coluna: df_0[coluna]})
          if goose_control_block in df_combinado:
            lista_coluna2 = [goose_control_block]
            lista_coluna2 = lista_coluna2+df_combinado[goose_control_block].tolist()

            cap_coluna1_text1.config(state='normal')
            cap_coluna1_text1.delete(0,tk.END)
            cap_coluna1_text1.insert(0,lista_coluna2[0])
            cap_coluna1_text1.config(state='readonly',readonlybackground='white')

            cap_coluna1_text2.config(state='normal')
            cap_coluna1_text2.delete(0,tk.END)
            cap_coluna1_text2.insert(0,lista_coluna2[1])
            cap_coluna1_text2.config(state='readonly',readonlybackground='white')

            cap_coluna1_text3.config(state='normal')
            cap_coluna1_text3.delete(0,tk.END)
            cap_coluna1_text3.insert(0,lista_coluna2[2])
            cap_coluna1_text3.config(state='readonly',readonlybackground='white')

            cap_coluna1_text4.config(state='normal')
            cap_coluna1_text4.delete(0,tk.END)
            cap_coluna1_text4.insert(0,lista_coluna2[3])
            cap_coluna1_text4.config(state='readonly',readonlybackground='white')

            cap_coluna1_text5.config(state='normal')
            cap_coluna1_text5.delete(0,tk.END)
            cap_coluna1_text5.insert(0,lista_coluna2[4])
            cap_coluna1_text5.config(state='readonly',readonlybackground='white')

            cap_coluna1_text6.config(state='normal')
            cap_coluna1_text6.delete(0,tk.END)
            cap_coluna1_text6.insert(0,lista_coluna2[5])
            cap_coluna1_text6.config(state='readonly',readonlybackground='white')

            cap_coluna1_text7.config(state='normal')
            cap_coluna1_text7.delete(0,tk.END)
            cap_coluna1_text7.insert(0,lista_coluna2[6])
            cap_coluna1_text7.config(state='readonly',readonlybackground='white')

            cap_coluna1_text8.config(state='normal')
            cap_coluna1_text8.delete(0,tk.END)
            cap_coluna1_text8.insert(0,lista_coluna2[7])
            cap_coluna1_text8.config(state='readonly',readonlybackground='white')

            cap_coluna1_text9.config(state='normal')
            cap_coluna1_text9.delete(0,tk.END)
            cap_coluna1_text9.insert(0,lista_coluna2[8])
            cap_coluna1_text9.config(state='readonly',readonlybackground='white')

            cap_coluna1_text10.config(state='normal')
            cap_coluna1_text10.delete(0,tk.END)
            cap_coluna1_text10.insert(0,lista_coluna2[9])
            cap_coluna1_text10.config(state='readonly',readonlybackground='white')

            if proj_coluna1_text2.get() != cap_coluna1_text2.get():
               cap_coluna2_imagem2.config(image=imagem)
            if proj_coluna1_text3.get() != cap_coluna1_text3.get():
               cap_coluna2_imagem3.config(image=imagem)
            if proj_coluna1_text4.get() != cap_coluna1_text4.get():
               cap_coluna2_imagem4.config(image=imagem)
            if proj_coluna1_text5.get() != cap_coluna1_text5.get():
               cap_coluna2_imagem5.config(image=imagem) 
            if proj_coluna1_text6.get() != cap_coluna1_text6.get():
               cap_coluna2_imagem6.config(image=imagem)
            if proj_coluna1_text7.get() != cap_coluna1_text7.get():
               cap_coluna2_imagem7.config(image=imagem) 
            if proj_coluna1_text8.get() != cap_coluna1_text8.get():
               cap_coluna2_imagem8.config(image=imagem)
            if proj_coluna1_text9.get() != cap_coluna1_text9.get():
               cap_coluna2_imagem9.config(image=imagem) 
            if proj_coluna1_text10.get() != cap_coluna1_text10.get():
               cap_coluna2_imagem10.config(image=imagem)
            time.sleep(1)
          else:
             oculta_imagem_atencao()
             
def start_capture():
    botao_pausar.config(state=tk.NORMAL)
    botao_refresh.config(state=tk.DISABLED)
    botao_pasta.config(state=tk.DISABLED)
    botao_find.config(state=tk.NORMAL)
    global capturing
    capturing = True
    capture_thread = Thread(target=capture_packets, args=(capturado_coluna1,))
    capture_thread.daemon = True
    capture_thread.start()

def stop_capture():
    botao_pausar.config(state=tk.DISABLED)
    botao_refresh.config(state=tk.NORMAL)
    botao_pasta.config(state=tk.NORMAL)
    botao_find.config(state=tk.DISABLED)
    global capturing
    capturing = False

def oculta_ied_prop():
   texto3.grid_forget()
   caixa_ied.grid_remove()

def mostra_ied_prop():
  caixa_ied.grid(column=0,row=6,sticky='n')
  texto3.grid(column=0,row=5,padx=(0,0))
  try:
      find_Communication = root.find(tag_xml+'Communication')
      find_ConnectedAP = find_Communication.findall(tag_xml+'ConnectedAP')
      find_IED = root.findall(tag_xml+'IED')
      for i in find_IED: 
         if(i.get('name') == devices.get()): 
          if i.get('manufacturer') == 'SIEMENS' or i.get('manufacturer') != 'ABB':
            for l in find_ConnectedAP:
              if i.get('name') == l.get('iedName'):
                find_ConnectedAP_Address = l.find(tag_xml+'Address')
                find_ConnectedAP_P = find_ConnectedAP_Address.findall(tag_xml+'P')
                for n in find_ConnectedAP_P:
                  if(n.get('type') == 'IP'):
                    caixa_ied_ip.config(state='normal')
                    caixa_ied_ip.delete(0,tk.END)
                    caixa_ied_ip.insert(0,n.text)
                    caixa_ied_ip.config(state='readonly',readonlybackground='white')

                    caixa_ied_manufacturer.config(state='normal')
                    caixa_ied_manufacturer.delete(0,tk.END)
                    caixa_ied_manufacturer.insert(0,i.get('manufacturer'))
                    caixa_ied_manufacturer.config(state='readonly',readonlybackground='white')

                    caixa_ied_type.config(state='normal')
                    caixa_ied_type.delete(0,tk.END)
                    caixa_ied_type.insert(0,i.get('type'))
                    caixa_ied_type.config(state='readonly',readonlybackground='white')
          elif i.get('manufacturer') == 'ABB':
            for l in find_ConnectedAP:
              if i.get('name') == l.get('iedName'):
                find_ConnectedAP_Address = l.find(tag_xml+'Address')
                find_ConnectedAP_P = find_ConnectedAP_Address.findall(tag_xml+'P')
                for n in find_ConnectedAP_P:
                  if(n.get('type') == 'IP'):
                    caixa_ied_ip.config(state='normal')
                    caixa_ied_ip.delete(0,tk.END)
                    caixa_ied_ip.insert(0,n.text)
                    caixa_ied_ip.config(state='readonly',readonlybackground='white')
            
                    caixa_ied_manufacturer.config(state='normal')
                    caixa_ied_manufacturer.delete(0,tk.END)
                    caixa_ied_manufacturer.insert(0,i.get('manufacturer'))
                    caixa_ied_manufacturer.config(state='readonly',readonlybackground='white')

                    caixa_ied_type.config(state='normal')
                    caixa_ied_type.delete(0,tk.END)
                    caixa_ied_type.insert(0,i.get('type'))
                    caixa_ied_type.config(state='readonly',readonlybackground='white')
          else:
            for l in find_ConnectedAP:
              if i.get('name') == l.get('iedName'):
                find_ConnectedAP_Address = l.find(tag_xml+'Address')
                find_ConnectedAP_P = find_ConnectedAP_Address.findall(tag_xml+'P')
                for n in find_ConnectedAP_P:
                  if(n.get('type') == 'IP'):
                    caixa_ied_ip.config(state='normal')
                    caixa_ied_ip.delete(0,tk.END)
                    caixa_ied_ip.insert(0,n.text)
                    caixa_ied_ip.config(state='readonly',readonlybackground='white')
                        
                    caixa_ied_manufacturer.config(state='normal')
                    caixa_ied_manufacturer.delete(0,tk.END)
                    caixa_ied_manufacturer.insert(0,i.get('manufacturer'))
                    caixa_ied_manufacturer.config(state='readonly',readonlybackground='white')

                    caixa_ied_type.config(state='normal')
                    caixa_ied_type.delete(0,tk.END)
                    caixa_ied_type.insert(0,i.get('type'))
                    caixa_ied_type.config(state='readonly',readonlybackground='white')

  except etree.XMLSyntaxError as e:
      print(f'Erro de sintaxe XML: {e}')
  except FileNotFoundError as e:
      print(f'Arquivo XML não encontrado: {e}')

def SCD_lista_devices():
  global Projeto_verificado
  Arquivo_SCD()
  arquivo_xml = Arquivo_SCD_path
  global tag_xml
  global root 
  try:
      tree = etree.parse(arquivo_xml)
      root = tree.getroot()
      tag_xml = root.tag.split('}')[0] + '}'
      tag_xml = './/'+tag_xml
      find_IED = root.findall(tag_xml+'IED')
      name_IED = []
      for i in find_IED: 
         name_IED.append(i.get('name'))
      devices["values"] = name_IED
      Projeto_verificado = name_IED
      Ativar_botao_iniciar('')
  
  except etree.XMLSyntaxError as e:
      print(f'Erro de sintaxe XML: {e}')
  except FileNotFoundError as e:
      print(f'Arquivo XML não encontrado: {e}')

def SCD_find():
  try:
      find_IED = root.findall(tag_xml+'IED')
      find_Communication = root.find(tag_xml+'Communication')
      find_ConnectedAP = find_Communication.findall(tag_xml+'ConnectedAP')
      
      name_IED = []
      manufacturer_IED = []
      GCB_IED = {}
      GCB_IED['gocbref'] = ['MAC-Addres','APPID','goID','datSet','VLAN_ID','VLAN_PRIORITY','confRev','timeAllowedtoLive','numDatSetEntries']
      for i in find_IED: 
         find_IED_Server = i.find(tag_xml+'Server')
         if find_IED_Server is not None:
          name_IED.append(i.get('name'))
          manufacturer_IED.append(i.get('manufacturer'))
          if i.get('manufacturer') == 'SIEMENS' or i.get('manufacturer') != 'ABB':
            find_IED_LDevice = find_IED_Server.findall(tag_xml+'LDevice')
            for j in find_IED_LDevice:
              find_IED_GSEControl = j.findall(tag_xml+'GSEControl')
              if len(find_IED_GSEControl) != 0:
                  lnType_IED = i.get('name')+j.get('inst')
                  for k in find_IED_GSEControl:
                      lista_chave =[]
                      name_GSEControl = k.get('name')

                      find_IED_LN0 = j.find(tag_xml+'LN0') 
                      datSet = find_IED_LN0.get('lnType')+'$'+k.get('datSet')

                      find_IED_DataSet = find_IED_LN0.findall(tag_xml+'DataSet')
                      numDatSetEntries = ''
                      for o in find_IED_DataSet:
                        if k.get('datSet') == o.get('name'):
                           find_IED_FCDA = o.findall(tag_xml+'FCDA')
                           numDatSetEntries = len(find_IED_FCDA)

                      for l in find_ConnectedAP:
                         if i.get('name') == l.get('iedName'):
                            find_ConnectedAP_GSE = l.findall(tag_xml+'GSE')
                            for m in find_ConnectedAP_GSE:
                               if (name_GSEControl == m.get('cbName')) and (j.get('inst') == m.get('ldInst') ):
                                find_ConnectedAP_Address = m.find(tag_xml+'Address')
                                find_ConnectedAP_MinTime = m.find(tag_xml+'MinTime')
                                find_ConnectedAP_MaxTime = m.find(tag_xml+'MaxTime')
                                MinTime_Maxtime = find_ConnectedAP_MinTime.text+find_ConnectedAP_MinTime.get('multiplier')+find_ConnectedAP_MinTime.get('unit')+'-'+find_ConnectedAP_MaxTime.text+find_ConnectedAP_MaxTime.get('multiplier')+find_ConnectedAP_MaxTime.get('unit')
                                find_ConnectedAP_P = find_ConnectedAP_Address.findall(tag_xml+'P')
                                VLAN_PRIORITY =''
                                VLAN_ID =''
                                for n in find_ConnectedAP_P:
                                   if n.get('type') == 'MAC-Address':
                                    lista_chave.append(n.text)
                                   if n.get('type') == 'APPID':
                                      lista_chave.append(n.text)  
                                   if n.get('type') == 'VLAN-PRIORITY':
                                      VLAN_PRIORITY = n.text
                                   if n.get('type') == 'VLAN-ID':
                                      VLAN_ID=n.text
                                break
                      lista_chave.append(k.get('appID'))
                      lista_chave.append(datSet)
                      lista_chave.append(VLAN_ID)
                      lista_chave.append(VLAN_PRIORITY)
                      lista_chave.append(k.get('confRev'))
                      lista_chave.append(MinTime_Maxtime)
                      lista_chave.append(numDatSetEntries)
                      GCB_IED[lnType_IED+'/LLN0$GO$'+name_GSEControl] = lista_chave

          elif i.get('manufacturer') == 'ABB':
            find_IED_LDevice = find_IED_Server.findall(tag_xml+'LDevice')
            for j in find_IED_LDevice:
             find_IED_GSEControl = j.findall(tag_xml+'GSEControl')
             if len(find_IED_GSEControl) != 0:
              for k in find_IED_GSEControl:
                  lista_chave=[]
                  GSEControl_appID = k.get('appID')
                  GSEControl_gocbref = GSEControl_appID.replace('.','$GO$')
                  find_num = GSEControl_appID.find('.')
                  len_string = len(GSEControl_appID)
                  name_GSEControl = GSEControl_appID[find_num+1:len_string]
                  datSet = GSEControl_appID[0:find_num]+'$'+k.get('datSet')
                  find_IED_LN0 = j.find(tag_xml+'LN0') 
                  find_IED_DataSet = find_IED_LN0.findall(tag_xml+'DataSet')
                  numDatSetEntries = ''
                  for o in find_IED_DataSet:
                    if k.get('datSet') == o.get('name'):
                      find_IED_FCDA = o.findall(tag_xml+'FCDA')
                      numDatSetEntries = len(find_IED_FCDA)
                  
                  for l in find_ConnectedAP:
                          if i.get('name') == l.get('iedName'):
                              find_ConnectedAP_GSE = l.findall(tag_xml+'GSE')
                              for m in find_ConnectedAP_GSE:
                                if (name_GSEControl == m.get('cbName')) and (j.get('inst') == m.get('ldInst') ):
                                  find_ConnectedAP_Address = m.find(tag_xml+'Address')
                                  find_ConnectedAP_MinTime = m.find(tag_xml+'MinTime')
                                  find_ConnectedAP_MaxTime = m.find(tag_xml+'MaxTime')
                                  MinTime_Maxtime = find_ConnectedAP_MinTime.text+find_ConnectedAP_MinTime.get('multiplier')+find_ConnectedAP_MinTime.get('unit')+'-'+find_ConnectedAP_MaxTime.text+find_ConnectedAP_MaxTime.get('multiplier')+find_ConnectedAP_MaxTime.get('unit')
                                  find_ConnectedAP_P = find_ConnectedAP_Address.findall(tag_xml+'P')
                                  for n in find_ConnectedAP_P:
                                    if n.get('type') == 'MAC-Address':
                                      lista_chave.append(n.text)
                                    if n.get('type') == 'APPID':
                                      lista_chave.append(n.text)
                                    if n.get('type') == 'VLAN-PRIORITY':
                                      VLAN_PRIORITY = n.text
                                    if n.get('type') == 'VLAN-ID':
                                      VLAN_ID=n.text
                                  break
                  lista_chave.append(k.get('appID'))
                  lista_chave.append(datSet)
                  lista_chave.append(VLAN_ID)
                  lista_chave.append(VLAN_PRIORITY)
                  lista_chave.append(k.get('confRev'))
                  lista_chave.append(MinTime_Maxtime)
                  lista_chave.append(numDatSetEntries)     
                  GCB_IED[GSEControl_gocbref] = lista_chave
                         
      df = pd.DataFrame(GCB_IED)
      return df
      
  except etree.XMLSyntaxError as e:
      print(f'Erro de sintaxe XML: {e}')
  except FileNotFoundError as e:
      print(f'Arquivo XML não encontrado: {e}')

def SCD(arr):
  goose_control_block = devices.get()+goose.get()+'/'+dataset.get()
  goose_control_block=goose_control_block.replace('.','$GO$')
  try:
      find_IED = root.findall(tag_xml+'IED')
      find_Communication = root.find(tag_xml+'Communication')
      find_ConnectedAP = find_Communication.findall(tag_xml+'ConnectedAP')
      name_IED = []
      manufacturer_IED = []
      GCB_IED = {}
      GCB_IED['gocbref'] = ['MAC-Addres','APPID','goID','datSet','VLAN_ID','VLAN_PRIORITY','confRev','timeAllowedtoLive','numDatSetEntries']
      for i in find_IED: 
         find_IED_Server = i.find(tag_xml+'Server')
         if find_IED_Server is not None:
          name_IED.append(i.get('name'))
          manufacturer_IED.append(i.get('manufacturer'))
          if i.get('manufacturer') == 'SIEMENS' or i.get('manufacturer') != 'ABB':
            find_IED_LDevice = find_IED_Server.findall(tag_xml+'LDevice')
            for j in find_IED_LDevice:
              find_IED_GSEControl = j.findall(tag_xml+'GSEControl')
              if len(find_IED_GSEControl) != 0:
                  lnType_IED = i.get('name')+j.get('inst')
                  for k in find_IED_GSEControl:
                      lista_chave =[]
                      name_GSEControl = k.get('name')
                      datSet = i.get('name')+j.get('inst')+'/LLN0$'+k.get('datSet')
                      find_IED_DataSet = j.findall(tag_xml+'DataSet')
                      numDatSetEntries = ''
                      for o in find_IED_DataSet:
                        if k.get('datSet') == o.get('name'):
                           find_IED_FCDA = o.findall(tag_xml+'FCDA')
                           numDatSetEntries = len(find_IED_FCDA)
                      for l in find_ConnectedAP:
                         if i.get('name') == l.get('iedName'):
                            find_ConnectedAP_GSE = l.findall(tag_xml+'GSE')
                            for m in find_ConnectedAP_GSE:
                               if (name_GSEControl == m.get('cbName')) and (j.get('inst') == m.get('ldInst') ):
                                find_ConnectedAP_MaxTime = m.find(tag_xml+'MaxTime')
                                MinTime_Maxtime = find_ConnectedAP_MaxTime.text
                                find_ConnectedAP_P = m.findall(tag_xml+'P')
                                VLAN_PRIORITY =''
                                VLAN_ID =''
                                for n in find_ConnectedAP_P:
                                   if n.get('type') == 'MAC-Address':
                                    lista_chave.append(n.text)
                                   if n.get('type') == 'APPID':
                                      APPID = '0x'+n.text
                                      lista_chave.append(APPID)   
                                   if n.get('type') == 'VLAN-PRIORITY':
                                      VLAN_PRIORITY = n.text
                                   if n.get('type') == 'VLAN-ID':
                                      VLAN_ID=n.text
                                break
                      lista_chave.append(k.get('appID'))
                      lista_chave.append(datSet)
                      lista_chave.append(VLAN_ID)
                      lista_chave.append(VLAN_PRIORITY)
                      lista_chave.append(k.get('confRev'))
                      lista_chave.append(MinTime_Maxtime)
                      lista_chave.append(numDatSetEntries)
                      GCB_IED[lnType_IED+'/LLN0$GO$'+name_GSEControl] = lista_chave
          elif i.get('manufacturer') == 'ABB':
            find_IED_LDevice = find_IED_Server.findall(tag_xml+'LDevice')
            for j in find_IED_LDevice:
             find_IED_GSEControl = j.findall(tag_xml+'GSEControl')
             if len(find_IED_GSEControl) != 0:
              for k in find_IED_GSEControl:
                  lista_chave=[]
                  GSEControl_appID = k.get('appID')
                  GSEControl_gocbref = GSEControl_appID.replace('.','$GO$')
                  find_num = GSEControl_appID.find('.')
                  len_string = len(GSEControl_appID)
                  name_GSEControl = GSEControl_appID[find_num+1:len_string]
                  datSet = i.get('name')+j.get('inst')+'/LLN0$'+k.get('datSet')
                  find_IED_DataSet = j.findall(tag_xml+'DataSet')
                  numDatSetEntries = ''
                  for o in find_IED_DataSet:
                    if k.get('datSet') == o.get('name'):
                      find_IED_FCDA = o.findall(tag_xml+'FCDA')
                      numDatSetEntries = len(find_IED_FCDA)
                  for l in find_ConnectedAP:
                          if i.get('name') == l.get('iedName'):
                              find_ConnectedAP_GSE = l.findall(tag_xml+'GSE')
                              for m in find_ConnectedAP_GSE:
                                if (name_GSEControl == m.get('cbName')) and (j.get('inst') == m.get('ldInst') ):
                                  find_ConnectedAP_MaxTime = m.find(tag_xml+'MaxTime')
                                  MinTime_Maxtime = find_ConnectedAP_MaxTime.text
                                  find_ConnectedAP_P = m.findall(tag_xml+'P')
                                  for n in find_ConnectedAP_P:
                                    if n.get('type') == 'MAC-Address':
                                      lista_chave.append(n.text)
                                    if n.get('type') == 'APPID':
                                      APPID = '0x'+n.text
                                      lista_chave.append(APPID)
                                    if n.get('type') == 'VLAN-PRIORITY':
                                      VLAN_PRIORITY = n.text
                                    if n.get('type') == 'VLAN-ID':
                                      VLAN_ID=n.text
                                  break
                  lista_chave.append(k.get('appID'))
                  lista_chave.append(datSet)
                  lista_chave.append(VLAN_ID)
                  lista_chave.append(VLAN_PRIORITY)
                  lista_chave.append(k.get('confRev'))
                  lista_chave.append(MinTime_Maxtime)
                  lista_chave.append(numDatSetEntries)     
                  GCB_IED[GSEControl_gocbref] = lista_chave          
      df = pd.DataFrame(GCB_IED)
      coluna_fixa = df.columns[0]
      for coluna in df.columns[1:]:
          df_combinado = pd.DataFrame({coluna_fixa: df[coluna_fixa], coluna: df[coluna]})
          if goose_control_block in df_combinado:
             lista_coluna1 = ['gocbref']
             lista_coluna1 = lista_coluna1+df['gocbref'].tolist()
             lista_coluna2 = [goose_control_block]
             lista_coluna2 = lista_coluna2+df[goose_control_block].tolist()

             proj_coluna1_text1.config(state='normal')
             proj_coluna1_text1.delete(0,tk.END)
             proj_coluna1_text1.insert(0,lista_coluna2[0])
             proj_coluna1_text1.config(state='readonly',readonlybackground='white')

             proj_coluna1_text2.config(state='normal')
             proj_coluna1_text2.delete(0,tk.END)
             proj_coluna1_text2.insert(0,lista_coluna2[1])
             proj_coluna1_text2.config(state='readonly',readonlybackground='white')

             proj_coluna1_text3.config(state='normal')
             proj_coluna1_text3.delete(0,tk.END)
             proj_coluna1_text3.insert(0,lista_coluna2[2])
             proj_coluna1_text3.config(state='readonly',readonlybackground='white')

             proj_coluna1_text4.config(state='normal')
             proj_coluna1_text4.delete(0,tk.END)
             proj_coluna1_text4.insert(0,lista_coluna2[3])
             proj_coluna1_text4.config(state='readonly',readonlybackground='white')

             proj_coluna1_text5.config(state='normal')
             proj_coluna1_text5.delete(0,tk.END)
             proj_coluna1_text5.insert(0,lista_coluna2[4])
             proj_coluna1_text5.config(state='readonly',readonlybackground='white')

             proj_coluna1_text6.config(state='normal')
             proj_coluna1_text6.delete(0,tk.END)
             proj_coluna1_text6.insert(0,lista_coluna2[5])
             proj_coluna1_text6.config(state='readonly',readonlybackground='white')

             proj_coluna1_text7.config(state='normal')
             proj_coluna1_text7.delete(0,tk.END)
             proj_coluna1_text7.insert(0,lista_coluna2[6])
             proj_coluna1_text7.config(state='readonly',readonlybackground='white')

             proj_coluna1_text8.config(state='normal')
             proj_coluna1_text8.delete(0,tk.END)
             proj_coluna1_text8.insert(0,lista_coluna2[7])
             proj_coluna1_text8.config(state='readonly',readonlybackground='white')

             proj_coluna1_text9.config(state='normal')
             proj_coluna1_text9.delete(0,tk.END)
             proj_coluna1_text9.insert(0,lista_coluna2[8])
             proj_coluna1_text9.config(state='readonly',readonlybackground='white')

             proj_coluna1_text10.config(state='normal')
             proj_coluna1_text10.delete(0,tk.END)
             proj_coluna1_text10.insert(0,lista_coluna2[9])
             proj_coluna1_text10.config(state='readonly',readonlybackground='white')

             oculta_imagem_atencao()
             ocultar_dados_capturado()
  except etree.XMLSyntaxError as e:
      print(f'Erro de sintaxe XML: {e}')
  except FileNotFoundError as e:
      print(f'Arquivo XML não encontrado: {e}')

def Selecionar_Dispositivo(arr):
  oculta_ied_prop()
  try:
      find_IED = root.findall(tag_xml+'IED')
      for i in find_IED: 
         find_IED_Server = i.find(tag_xml+'Server')
         if find_IED_Server is not None:
          if i.get('name') == devices.get(): 
              ied_prop.grid(column=0,row=2,padx=(40,40),pady=(0,20))
              if i.get('manufacturer') == 'SIEMENS' or i.get('manufacturer') != 'ABB':
                find_IED_LDevice = find_IED_Server.findall(tag_xml+'LDevice')
                for j in find_IED_LDevice:
                  find_IED_GSEControl = j.findall(tag_xml+'GSEControl')
                  if len(find_IED_GSEControl) != 0:
                    goose.grid(column=0,row=3,padx=(40,40),pady=(0,20)) 
                    SCD_Lista_LDs(devices.get())
                    return
                  else:
                    goose.grid_forget()
                    dataset.grid_forget()
                    ocultar_dados_projeto()
                    ocultar_dados_capturado()  
                    oculta_imagem_atencao() 

              elif i.get('manufacturer') == 'ABB':
                find_IED_LDevice = find_IED_Server.findall(tag_xml+'LDevice')
                for j in find_IED_LDevice:
                  find_IED_GSEControl = j.findall(tag_xml+'GSEControl')
                  if len(find_IED_GSEControl) != 0:
                    goose.grid(column=0,row=3,padx=(40,40),pady=(0,20))
                    SCD_Lista_LDs(devices.get())
                    return
                  else:
                    goose.grid_forget()
                    dataset.grid_forget()

                    ocultar_dados_projeto()
                    ocultar_dados_capturado()   
                    oculta_imagem_atencao()

         if i.get('name') == devices.get(): 
          ied_prop.grid(column=0,row=2,padx=(40,40),pady=(0,20))  
          goose.grid_forget()
          dataset.grid_forget()

          ocultar_dados_projeto()
          ocultar_dados_capturado() 
          oculta_imagem_atencao()  

  except etree.XMLSyntaxError as e:
      print(f'Erro de sintaxe XML: {e}')
  except FileNotFoundError as e:
      print(f'Arquivo XML não encontrado: {e}')

def SCD_Lista_LDs(Dispositivo_escolhido):
  try:
      find_IED = root.findall(tag_xml+'IED')
      lista_LDs=[]
      for i in find_IED: 
        find_IED_Server = i.find(tag_xml+'Server')
        if find_IED_Server is not None:
          if i.get('manufacturer') == 'SIEMENS' or i.get('manufacturer') != 'ABB':
            find_IED_LDevice = find_IED_Server.findall(tag_xml+'LDevice')
            for j in find_IED_LDevice:
              find_IED_GSEControl = j.findall(tag_xml+'GSEControl')
              if len(find_IED_GSEControl) != 0:
                if(Dispositivo_escolhido==i.get('name')):
                  lista_LDs.append(j.get('inst'))
          elif i.get('manufacturer') == 'ABB':
            find_IED_LDevice = find_IED_Server.findall(tag_xml+'LDevice')
            for j in find_IED_LDevice:
              find_IED_GSEControl = j.findall(tag_xml+'GSEControl')
              if len(find_IED_GSEControl) != 0:
                if(Dispositivo_escolhido==i.get('name')):
                  lista_LDs.append(j.get('inst'))#
      goose.set('Goose')
      goose["values"] = lista_LDs
      dataset.grid_forget()
      ocultar_dados_projeto()
      ocultar_dados_capturado()   

  except etree.XMLSyntaxError as e:
      print(f'Erro de sintaxe XML: {e}')
  except FileNotFoundError as e:
      print(f'Arquivo XML não encontrado: {e}')  

def iniciar():
   packet_callback(Interface_de_rede())
  
def SCD_lista_dataset(arr):
  try:
      find_IED = root.findall(tag_xml+'IED')
      dataset_lista = []
      for i in find_IED: 
         if devices.get()==i.get('name'):
          find_IED_Server = i.find(tag_xml+'Server')
          if i.get('manufacturer') == 'SIEMENS' or i.get('manufacturer') == 'ABB':
            find_IED_LDevice = find_IED_Server.findall(tag_xml+'LDevice')
            for j in find_IED_LDevice:
              find_IED_GSEControl = j.findall(tag_xml+'GSEControl')
              if len(find_IED_GSEControl) != 0:
                for k in find_IED_GSEControl:
                  if j.get('inst') == goose.get():
                    dataset_lista.append('LLN0.'+k.get('name'))
          elif i.get('manufacturer') == 'ABB':
            find_IED_LDevice = find_IED_Server.findall(tag_xml+'LDevice')
            for j in find_IED_LDevice:
              find_IED_GSEControl = j.findall(tag_xml+'GSEControl')
              if len(find_IED_GSEControl) != 0:
                for k in find_IED_GSEControl:
                  if j.get('inst') == goose.get():
                    dataset_lista.append('LLN0.'+k.get('name')) 
      dataset.grid(column=0,row=4,padx=(40,40),pady=(0,20))
      dataset.set('Dataset')
      dataset['values'] = dataset_lista
      ocultar_dados_projeto()
      ocultar_dados_capturado()  
      oculta_imagem_atencao() 
  except etree.XMLSyntaxError as e:
      print(f'Erro de sintaxe XML: {e}')
  except FileNotFoundError as e:
      print(f'Arquivo XML não encontrado: {e}')

def ocultar_botao():
  goose.grid_forget()

def ocultar_dados_projeto():
  proj_coluna1_text1.config(state='normal')
  proj_coluna1_text1.delete(0,tk.END)
  proj_coluna1_text1.insert(0,'')
  proj_coluna1_text1.config(state='readonly',readonlybackground='white')

  proj_coluna1_text2.config(state='normal')
  proj_coluna1_text2.delete(0,tk.END)
  proj_coluna1_text2.insert(0,'')
  proj_coluna1_text2.config(state='readonly',readonlybackground='white')

  proj_coluna1_text3.config(state='normal')
  proj_coluna1_text3.delete(0,tk.END)
  proj_coluna1_text3.insert(0,'')
  proj_coluna1_text3.config(state='readonly',readonlybackground='white')

  proj_coluna1_text4.config(state='normal')
  proj_coluna1_text4.delete(0,tk.END)
  proj_coluna1_text4.insert(0,'')
  proj_coluna1_text4.config(state='readonly',readonlybackground='white')

  proj_coluna1_text5.config(state='normal')
  proj_coluna1_text5.delete(0,tk.END)
  proj_coluna1_text5.insert(0,'')
  proj_coluna1_text5.config(state='readonly',readonlybackground='white')

  proj_coluna1_text6.config(state='normal')
  proj_coluna1_text6.delete(0,tk.END)
  proj_coluna1_text6.insert(0,'')
  proj_coluna1_text6.config(state='readonly',readonlybackground='white')

  proj_coluna1_text7.config(state='normal')
  proj_coluna1_text7.delete(0,tk.END)
  proj_coluna1_text7.insert(0,'')
  proj_coluna1_text7.config(state='readonly',readonlybackground='white')

  proj_coluna1_text8.config(state='normal')
  proj_coluna1_text8.delete(0,tk.END)
  proj_coluna1_text8.insert(0,'')
  proj_coluna1_text8.config(state='readonly',readonlybackground='white')

  proj_coluna1_text9.config(state='normal')
  proj_coluna1_text9.delete(0,tk.END)
  proj_coluna1_text9.insert(0,'')
  proj_coluna1_text9.config(state='readonly',readonlybackground='white')

  proj_coluna1_text10.config(state='normal')
  proj_coluna1_text10.delete(0,tk.END)
  proj_coluna1_text10.insert(0,'')
  proj_coluna1_text10.config(state='readonly',readonlybackground='white')
   
def ocultar_dados_capturado():
  cap_coluna1_text1.config(state='normal')
  cap_coluna1_text1.delete(0,tk.END)
  cap_coluna1_text1.insert(0,'')
  cap_coluna1_text1.config(state='readonly',readonlybackground='white')

  cap_coluna1_text2.config(state='normal')
  cap_coluna1_text2.delete(0,tk.END)
  cap_coluna1_text2.insert(0,'')
  cap_coluna1_text2.config(state='readonly',readonlybackground='white')

  cap_coluna1_text3.config(state='normal')
  cap_coluna1_text3.delete(0,tk.END)
  cap_coluna1_text3.insert(0,'')
  cap_coluna1_text3.config(state='readonly',readonlybackground='white')

  cap_coluna1_text4.config(state='normal')
  cap_coluna1_text4.delete(0,tk.END)
  cap_coluna1_text4.insert(0,'')
  cap_coluna1_text4.config(state='readonly',readonlybackground='white')

  cap_coluna1_text5.config(state='normal')
  cap_coluna1_text5.delete(0,tk.END)
  cap_coluna1_text5.insert(0,'')
  cap_coluna1_text5.config(state='readonly',readonlybackground='white')

  cap_coluna1_text6.config(state='normal')
  cap_coluna1_text6.delete(0,tk.END)
  cap_coluna1_text6.insert(0,'')
  cap_coluna1_text6.config(state='readonly',readonlybackground='white')

  cap_coluna1_text7.config(state='normal')
  cap_coluna1_text7.delete(0,tk.END)
  cap_coluna1_text7.insert(0,'')
  cap_coluna1_text7.config(state='readonly',readonlybackground='white')

  cap_coluna1_text8.config(state='normal')
  cap_coluna1_text8.delete(0,tk.END)
  cap_coluna1_text8.insert(0,'')
  cap_coluna1_text8.config(state='readonly',readonlybackground='white')

  cap_coluna1_text9.config(state='normal')
  cap_coluna1_text9.delete(0,tk.END)
  cap_coluna1_text9.insert(0,'')
  cap_coluna1_text9.config(state='readonly',readonlybackground='white')

  cap_coluna1_text10.config(state='normal')
  cap_coluna1_text10.delete(0,tk.END)
  cap_coluna1_text10.insert(0,'')
  cap_coluna1_text10.config(state='readonly',readonlybackground='white')

def mostra_imagem_atencao():

  cap_coluna2_imagem1.grid(column=2,row = 0,sticky='w',padx=(0,8),pady=(4,0))  

  cap_coluna2_imagem2.grid(column=2,row = 1,sticky='w',padx=(0,8),pady=(9,0))  

  cap_coluna2_imagem3.grid(column=2,row = 2,sticky='w',padx=(0,8),pady=(9,0))  

  cap_coluna2_imagem4.grid(column=2,row = 3,sticky='w',padx=(0,8),pady=(9,0))  

  cap_coluna2_imagem5.grid(column=2,row = 4,sticky='w',padx=(0,8),pady=(9,0))  

  cap_coluna2_imagem6.grid(column=2,row = 5,sticky='w',padx=(0,8),pady=(10,0))  

  cap_coluna2_imagem7.grid(column=2,row = 6,sticky='w',padx=(0,8),pady=(9,0))  

  cap_coluna2_imagem8.grid(column=2,row = 7,sticky='w',padx=(0,8),pady=(9,0))  

  cap_coluna2_imagem9.grid(column=2,row = 8,sticky='w',padx=(0,8),pady=(9,0)) 

  cap_coluna2_imagem10.grid(column=2,row = 9,sticky='w',padx=(0,8),pady=(9,0)) 

def oculta_imagem_atencao():

  imagem_empty = PhotoImage(file="Icones\empty.png")

  cap_coluna2_imagem1.config(image=imagem_empty)
 
  cap_coluna2_imagem2.config(image=imagem_empty)
  cap_coluna2_imagem3.config(image=imagem_empty)
  cap_coluna2_imagem4.config(image=imagem_empty)
  cap_coluna2_imagem5.config(image=imagem_empty)
  cap_coluna2_imagem6.config(image=imagem_empty)
  cap_coluna2_imagem7.config(image=imagem_empty)
  cap_coluna2_imagem8.config(image=imagem_empty)
  cap_coluna2_imagem9.config(image=imagem_empty)
  cap_coluna2_imagem10.config(image=imagem_empty)

def find_parametros(h):
   goose_control_block_find = find_GOOSE.get()
   coluna_fixa_find = Dataframe_capturado.columns[0]
   for coluna in Dataframe_capturado.columns[1:]:
     df_combinado_find = pd.DataFrame({coluna_fixa_find: Dataframe_capturado[coluna_fixa_find], coluna: Dataframe_capturado[coluna]})
     if goose_control_block_find in df_combinado_find:
       lista_coluna_find = [goose_control_block_find]
       lista_coluna_find = lista_coluna_find+df_combinado_find[goose_control_block_find].tolist()

       find_coluna1_text1.config(state='normal')
       find_coluna1_text1.delete(0,tk.END)
       find_coluna1_text1.insert(0,lista_coluna_find[0])
       find_coluna1_text1.config(state='readonly',readonlybackground='white')

       find_coluna1_text2.config(state='normal')
       find_coluna1_text2.delete(0,tk.END)
       find_coluna1_text2.insert(0,lista_coluna_find[1])
       find_coluna1_text2.config(state='readonly',readonlybackground='white')

       find_coluna1_text3.config(state='normal')
       find_coluna1_text3.delete(0,tk.END)
       find_coluna1_text3.insert(0,lista_coluna_find[2])
       find_coluna1_text3.config(state='readonly',readonlybackground='white')

       find_coluna1_text4.config(state='normal')
       find_coluna1_text4.delete(0,tk.END)
       find_coluna1_text4.insert(0,lista_coluna_find[3])
       find_coluna1_text4.config(state='readonly',readonlybackground='white')

       find_coluna1_text5.config(state='normal')
       find_coluna1_text5.delete(0,tk.END)
       find_coluna1_text5.insert(0,lista_coluna_find[4])
       find_coluna1_text5.config(state='readonly',readonlybackground='white')

       find_coluna1_text6.config(state='normal')
       find_coluna1_text6.delete(0,tk.END)
       find_coluna1_text6.insert(0,lista_coluna_find[5])
       find_coluna1_text6.config(state='readonly',readonlybackground='white')

       find_coluna1_text7.config(state='normal')
       find_coluna1_text7.delete(0,tk.END)
       find_coluna1_text7.insert(0,lista_coluna_find[6])
       find_coluna1_text7.config(state='readonly',readonlybackground='white')

       find_coluna1_text8.config(state='normal')
       find_coluna1_text8.delete(0,tk.END)
       find_coluna1_text8.insert(0,lista_coluna_find[7])
       find_coluna1_text8.config(state='readonly',readonlybackground='white')

       find_coluna1_text9.config(state='normal')
       find_coluna1_text9.delete(0,tk.END)
       find_coluna1_text9.insert(0,lista_coluna_find[8])
       find_coluna1_text9.config(state='readonly',readonlybackground='white')

       find_coluna1_text10.config(state='normal')
       find_coluna1_text10.delete(0,tk.END)
       find_coluna1_text10.insert(0,lista_coluna_find[9])
       find_coluna1_text10.config(state='readonly',readonlybackground='white')

def Selecionar_Find():
   colunas_capturado = list(Dataframe_capturado.columns)
   colunas_capturado.remove('gocbref')
   Dataframe_projeto = SCD_find()
   colunas_projeto = list(Dataframe_projeto.columns)
   colunas_projeto.remove('gocbref')
   colunas_nao_encontrados = [item for item in colunas_capturado if item not in colunas_projeto]
   return colunas_nao_encontrados

def find():
   global find_GOOSE
   global find_coluna0_text1
   global find_coluna1_text1 
   global find_coluna0_text2 
   global find_coluna1_text2 
   global find_coluna0_text3
   global find_coluna1_text3 
   global find_coluna0_text4 
   global find_coluna1_text4 
   global find_coluna0_text5 
   global find_coluna1_text5 
   global find_coluna0_text6 
   global find_coluna1_text6 
   global find_coluna0_text7 
   global find_coluna1_text7 
   global find_coluna0_text8 
   global find_coluna1_text8 
   global find_coluna0_text9 
   global find_coluna1_text9 
   global find_coluna0_text10 
   global find_coluna1_text10 
   janela2 = tk.Tk()
   janela2.title("Procurar")
   janela2.resizable(False,False)
   janela2.iconbitmap(os.path.abspath('Icones\eletrobras.ico'))

   textos_titulo_find_GOOSE = tk.Frame(janela2)
   textos_titulo_find_GOOSE.grid(column=0,row=0,sticky='n',padx=(0,0),pady=(10,10))

   textos_titulo_find_parametros = tk.Frame(janela2)
   textos_titulo_find_parametros.grid(column=1,row=0,sticky='n',padx=(0,0),pady=(10,10))
  
   parametros_find_GOOSE = tk.Frame(textos_titulo_find_GOOSE)
   parametros_find_GOOSE.grid(column=0,row=1,sticky='w',padx=(10,10),pady=(10,10))

   cor_coluna_0 = '#bcc0d6'
   cor_coluna_1 = 'white'

   find_coluna0 = tk.Frame(textos_titulo_find_parametros,bg=cor_coluna_0)
   find_coluna0.grid(column=0,row=1,sticky='n')

   find_coluna1= tk.Frame(textos_titulo_find_parametros)
   find_coluna1.grid(column=1,row=1,sticky='n')

   texto1_find = tk.Label(textos_titulo_find_GOOSE, text=" ",anchor='center')
   texto1_find.grid(column=0,row=0)

   texto2_find = tk.Label(textos_titulo_find_parametros, text="NÃO CONFIGURADO NO ARQUIVO SCL",anchor='center')
   texto2_find.grid(column=0,row=0)

   lista = Selecionar_Find()

   find_GOOSE = ttk.Combobox(parametros_find_GOOSE,values=lista, state="readonly",width=40)
   find_GOOSE.grid(column=0,row=0,padx=(10,10),pady=(0,5))
   find_GOOSE.set('GoCBRef')
   find_GOOSE.bind("<<ComboboxSelected>>",find_parametros)

   find_coluna0_text1 = tk.Label(find_coluna0,text='Control block reference',anchor='w',bg=cor_coluna_0)
   find_coluna0_text1.grid(column=0,row=0,padx=(5,10),pady=(5,0),sticky='wn')

   find_coluna1_text1 = tk.Entry(find_coluna0,bg=cor_coluna_1,justify='left',width=50)
   find_coluna1_text1.insert(0,'')
   find_coluna1_text1.grid(column=1,row=0,padx=(5,10),pady=(7,0),sticky='w')
   find_coluna1_text1.config(state='readonly',readonlybackground='white')

   find_coluna0_text2 = tk.Label(find_coluna0,text='Destination MAC address',anchor='w',bg=cor_coluna_0)
   find_coluna0_text2.grid(column=0,row=1,padx=(5,10),pady=(10,0),sticky='w')

   find_coluna1_text2 = tk.Entry(find_coluna0,bg=cor_coluna_1,justify='left',width=50)
   find_coluna1_text2.insert(0,'')
   find_coluna1_text2.grid(column=1,row=1,padx=(5,10),pady=(10,0))
   find_coluna1_text2.config(state='readonly',readonlybackground='white')

   find_coluna0_text3 = tk.Label(find_coluna0,text='Application ID',anchor='w',bg=cor_coluna_0)
   find_coluna0_text3.grid(column=0,row=2,padx=(5,10),pady=(10,0),sticky='w')

   find_coluna1_text3 = tk.Entry(find_coluna0,bg=cor_coluna_1,justify='left',width=50)
   find_coluna1_text3.insert(0,'')
   find_coluna1_text3.grid(column=1,row=2,padx=(5,10),pady=(11,0))
   find_coluna1_text3.config(state='readonly',readonlybackground='white')

   find_coluna0_text4 = tk.Label(find_coluna0,text='GOOSE ID',anchor='w',bg=cor_coluna_0)
   find_coluna0_text4.grid(column=0,row=3,padx=(5,10),pady=(10,0),sticky='w')

   find_coluna1_text4 = tk.Entry(find_coluna0,bg=cor_coluna_1,justify='left',width=50)
   find_coluna1_text4.insert(0,'')
   find_coluna1_text4.grid(column=1,row=3,padx=(5,10),pady=(11,0))
   find_coluna1_text4.config(state='readonly',readonlybackground='white')

   find_coluna0_text5 = tk.Label(find_coluna0,text='DataSet reference',anchor='w',bg=cor_coluna_0)
   find_coluna0_text5.grid(column=0,row=4,padx=(5,10),pady=(10,0),sticky='w')

   find_coluna1_text5 = tk.Entry(find_coluna0,bg=cor_coluna_1,justify='left',width=50)
   find_coluna1_text5.insert(0,'')
   find_coluna1_text5.grid(column=1,row=4,padx=(5,10),pady=(12,0))
   find_coluna1_text5.config(state='readonly',readonlybackground='white')

   find_coluna0_text6 = tk.Label(find_coluna0,text='VLAN ID',anchor='w',bg=cor_coluna_0)
   find_coluna0_text6.grid(column=0,row=5,padx=(5,10),pady=(10,0),sticky='w')

   find_coluna1_text6 = tk.Entry(find_coluna0,bg=cor_coluna_1,justify='left',width=50)
   find_coluna1_text6.insert(0,'')
   find_coluna1_text6.grid(column=1,row=5,padx=(5,10),pady=(13,0))
   find_coluna1_text6.config(state='readonly',readonlybackground='white')

   find_coluna0_text7 = tk.Label(find_coluna0,text='VLAN priority',anchor='w',bg=cor_coluna_0)
   find_coluna0_text7.grid(column=0,row=6,padx=(5,10),pady=(10,0),sticky='w')

   find_coluna1_text7 = tk.Entry(find_coluna0,bg=cor_coluna_1,justify='left',width=50)
   find_coluna1_text7.insert(0,'')
   find_coluna1_text7.grid(column=1,row=6,padx=(5,10),pady=(12,0))
   find_coluna1_text7.config(state='readonly',readonlybackground='white')

   find_coluna0_text8 = tk.Label(find_coluna0,text='Configuration revision',anchor='w',bg=cor_coluna_0)
   find_coluna0_text8.grid(column=0,row=7,padx=(5,10),pady=(10,0),sticky='w')

   find_coluna1_text8 = tk.Entry(find_coluna0,bg=cor_coluna_1,justify='left',width=50)
   find_coluna1_text8.insert(0,'')
   find_coluna1_text8.grid(column=1,row=7,padx=(5,10),pady=(12,0))
   find_coluna1_text8.config(state='readonly',readonlybackground='white')

   find_coluna0_text9 = tk.Label(find_coluna0,text='TimeAllowedtoLive',anchor='w',bg=cor_coluna_0)
   find_coluna0_text9.grid(column=0,row=8,padx=(5,10),pady=(10,0),sticky='w')

   find_coluna1_text9 = tk.Entry(find_coluna0,bg=cor_coluna_1,justify='left',width=50)
   find_coluna1_text9.insert(0,'')
   find_coluna1_text9.grid(column=1,row=8,padx=(5,10),pady=(12,0))
   find_coluna1_text9.config(state='readonly',readonlybackground='white')

   find_coluna0_text10 = tk.Label(find_coluna0,text='NumDatSetEntries',anchor='w',bg=cor_coluna_0)
   find_coluna0_text10.grid(column=0,row=9,padx=(5,10),pady=(10,5),sticky='w')

   find_coluna1_text10 = tk.Entry(find_coluna0,bg=cor_coluna_1,justify='left',width=50)
   find_coluna1_text10.insert(0,'')
   find_coluna1_text10.grid(column=1,row=9,padx=(5,10),pady=(12,5))
   find_coluna1_text10.config(state='readonly',readonlybackground='white')

   janela2.mainloop()

def Ativar_botao_iniciar(k):
   global Projeto_verificado

   if (Projeto_verificado is not None) and (redes.get() != 'Selecione a Rede'):
     botao_iniciar.config(state=tk.NORMAL)

aux = 1

# =================================================== INTERFACE DE USUÁRIO =========================================++++++++==================== #

janela = tk.Tk() 
janela.resizable(False,False)
janela.iconbitmap(os.path.abspath('Icones\eletrobras.ico'))


janela.title("Analisador de rede") 

# SUBMATRIZ DE JANELA - BOTÕES
botoes = tk.Frame(janela)
botoes.grid(column=0,row=0,sticky='w',padx=(10,0))

#SUBMATRIZ DE JANELA - PARAMETROS
parametros = tk.Frame(janela)
parametros.grid(column=0,row=1,sticky='w')

#SUBMATRIZ DE PARAMETROS - SPINNERS
spinners = tk.Frame(parametros,width=220,height=400)
spinners.grid_propagate(False)
#spinners = tk.Frame(parametros)
spinners.grid(column=0,row=0,sticky='n')

#SUBMATRIZ IED PROPERTIES
caixa_ied = tk.Frame(spinners)
caixa_ied.grid(column=0,row=6,sticky='n')

#SUBMATRIZ DE JANELA - TEXTO DO PROJETO
textos_titulo_projeto = tk.Frame(parametros)
textos_titulo_projeto.grid(column=1,row=0,sticky='n')

#SUBMATRIZ DE JANELA - TEXTO DO CAPTURADO
textos_titulo_capturado = tk.Frame(parametros)
textos_titulo_capturado.grid(column=2,row=0,sticky='n')

#SUBMATRIZ PARÂMETROS DO PROJETO
projeto = tk.Frame(textos_titulo_projeto)
projeto.grid(column=0,row=1,padx=(30,10),sticky='n')

#SUBMATRIZ PARÂMETROS DO CAPTURADO
capturado = tk.Frame(textos_titulo_capturado)
capturado.grid(column=0,row=1,padx=(10,30),sticky='n')

cor_coluna_0 = '#bcc0d6'
cor_coluna_1 = 'white'

#SUBMATRIZ PARÂMETROS DO PROJETO COLUNA 0
projeto_coluna0 = tk.Frame(projeto,bg=cor_coluna_0)
projeto_coluna0.grid(column=0,row=0,sticky='n')

#SUBMATRIZ PARÂMETROS DO PROJETO COLUNA 1
projeto_coluna1= tk.Frame(projeto)
projeto_coluna1.grid(column=1,row=0,sticky='n')

#SUBMATRIZ CAPTURADO DO PROJETO COLUNA 0
capturado_coluna0 = tk.Frame(capturado,bg=cor_coluna_0)
capturado_coluna0.grid(column=0,row=0,sticky='n')

#SUBMATRIZ CAPTURADO DO PROJETO COLUNA 1
capturado_coluna1= tk.Frame(capturado)
capturado_coluna1.grid(column=1,row=0,sticky='n')


# Textos de título
texto1 = tk.Label(textos_titulo_projeto, text="ARQUIVO SCL",anchor='center')
texto1.grid(column=0,row=0)

texto2 = tk.Label(textos_titulo_capturado, text="CAPTURADO PELA REDE",anchor='center')
texto2.grid(column=0,row=0)

# botoes
photo_pasta = tk.PhotoImage(file=os.path.abspath('Icones\pasta.png'))
botao_pasta = tk.Button(botoes, command=SCD_lista_devices,activebackground='light blue',image=photo_pasta,state=tk.NORMAL)
botao_pasta.grid(column=0,row=0,padx=(0,5),pady=(10,0)) 

photo_iniciar= tk.PhotoImage(file=os.path.abspath('Icones\play.png'))
botao_iniciar = tk.Button(botoes,activebackground='light blue',image=photo_iniciar,command=start_capture,state=tk.DISABLED)
botao_iniciar.grid(column=1,row=0,padx=(0,5),pady=(10,0))

photo_pausar= tk.PhotoImage(file=os.path.abspath('Icones\pause.png'))
botao_pausar = tk.Button(botoes,activebackground='light blue',image=photo_pausar,command=stop_capture,state=tk.DISABLED)
botao_pausar.grid(column=2,row=0,padx=(0,5),pady=(10,0))

photo_find= tk.PhotoImage(file=os.path.abspath('Icones\search.png'))
botao_find = tk.Button(botoes,command=find,activebackground='light blue',image=photo_find,state=tk.DISABLED)
botao_find.grid(column=3,row=0,padx=(0,5),pady=(10,0))

photo_eth_refresh= tk.PhotoImage(file=os.path.abspath('Icones\eth.png'))
botao_refresh = tk.Button(botoes,command=Lista_redes,activebackground='light blue',image=photo_eth_refresh,state=tk.NORMAL)
botao_refresh.grid(column=4,row=0,padx=(0,0),pady=(10,0))

# spinners
redes = ttk.Combobox(spinners, state="readonly") 
redes.grid(column=0,row=0,padx=(40,40),pady=(20,20)) 
redes.set('Selecione a Rede') 
redes.bind("<<ComboboxSelected>>",Ativar_botao_iniciar)

devices = ttk.Combobox(spinners, state="readonly")
devices.grid(column=0,row=1,padx=(40,40),pady=(0,20))
devices.set('Device')
devices.bind("<<ComboboxSelected>>",Selecionar_Dispositivo) 

ied_prop = tk.Button(spinners,text='        PROPRIEDADES        ',activebackground='light blue',command=mostra_ied_prop)

goose = ttk.Combobox(spinners,state="readonly")
goose.bind("<<ComboboxSelected>>",SCD_lista_dataset)

dataset = ttk.Combobox(spinners,state="readonly")
dataset.bind("<<ComboboxSelected>>",SCD)

#CAIXA IED PROPERTIES
texto3 = tk.Label(spinners, text="Propriedades do IED",anchor='center')
texto3.grid(column=0,row=5,padx=(0,0))

texto4 = tk.Label(caixa_ied, text="IP",anchor='w')
texto4.grid(column=0,row=0,padx=(5,10),pady=(10,0),sticky='w')

caixa_ied_ip = tk.Entry(caixa_ied,justify='center',bg='white')
caixa_ied_ip.insert(0,'')
caixa_ied_ip.grid(column=1,row=0,padx=(0,0),pady=(10,0))
caixa_ied_ip.config(state='readonly',readonlybackground='white')

texto5 = tk.Label(caixa_ied, text="Manufacturer",anchor='w')
texto5.grid(column=0,row=1,padx=(5,10),pady=(10,0),sticky='w')

caixa_ied_manufacturer = tk.Entry(caixa_ied,justify='center',bg='white')
caixa_ied_manufacturer.insert(0,'')
caixa_ied_manufacturer.grid(column=1,row=1,padx=(0,0),pady=(10,0))
caixa_ied_manufacturer.config(state='readonly',readonlybackground='white')

texto6 = tk.Label(caixa_ied, text="Type",anchor='w')
texto6.grid(column=0,row=2,padx=(5,10),pady=(10,0),sticky='w')

caixa_ied_type = tk.Entry(caixa_ied,justify='center',bg='white')
caixa_ied_type.insert(0,'')
caixa_ied_type.grid(column=1,row=2,padx=(0,0),pady=(10,0))
caixa_ied_type.config(state='readonly',readonlybackground='white')

# Matriz de parâmetros projeto
proj_coluna0_text1 = tk.Label(projeto_coluna0,text='Control block reference',anchor='w',bg=cor_coluna_0)
proj_coluna0_text1.grid(column=0,row=0,padx=(5,10),pady=(5,0),sticky='wn')

proj_coluna1_text1 = tk.Entry(projeto_coluna0,bg=cor_coluna_1,justify='left',width=50)
proj_coluna1_text1.insert(0,'')
proj_coluna1_text1.grid(column=1,row=0,padx=(5,10),pady=(7,0),sticky='w')
proj_coluna1_text1.config(state='readonly',readonlybackground='white')

proj_coluna0_text2 = tk.Label(projeto_coluna0,text='Destination MAC addres',anchor='w',bg=cor_coluna_0)
proj_coluna0_text2.grid(column=0,row=1,padx=(5,10),pady=(10,0),sticky='w')

proj_coluna1_text2 = tk.Entry(projeto_coluna0,bg=cor_coluna_1,justify='left',width=50)
proj_coluna1_text2.insert(0,'')
proj_coluna1_text2.grid(column=1,row=1,padx=(5,10),pady=(10,0))
proj_coluna1_text2.config(state='readonly',readonlybackground='white')

proj_coluna0_text3 = tk.Label(projeto_coluna0,text='Application ID',anchor='w',bg=cor_coluna_0)
proj_coluna0_text3.grid(column=0,row=2,padx=(5,10),pady=(10,0),sticky='w')

proj_coluna1_text3 = tk.Entry(projeto_coluna0,bg=cor_coluna_1,justify='left',width=50)
proj_coluna1_text3.insert(0,'')
proj_coluna1_text3.grid(column=1,row=2,padx=(5,10),pady=(11,0))
proj_coluna1_text3.config(state='readonly',readonlybackground='white')

proj_coluna0_text4 = tk.Label(projeto_coluna0,text='GOOSE ID',anchor='w',bg=cor_coluna_0)
proj_coluna0_text4.grid(column=0,row=3,padx=(5,10),pady=(10,0),sticky='w')

proj_coluna1_text4 = tk.Entry(projeto_coluna0,bg=cor_coluna_1,justify='left',width=50)
proj_coluna1_text4.insert(0,'')
proj_coluna1_text4.grid(column=1,row=3,padx=(5,10),pady=(11,0))
proj_coluna1_text4.config(state='readonly',readonlybackground='white')

proj_coluna0_text5 = tk.Label(projeto_coluna0,text='DataSet reference',anchor='w',bg=cor_coluna_0)
proj_coluna0_text5.grid(column=0,row=4,padx=(5,10),pady=(10,0),sticky='w')

proj_coluna1_text5 = tk.Entry(projeto_coluna0,bg=cor_coluna_1,justify='left',width=50)
proj_coluna1_text5.insert(0,'')
proj_coluna1_text5.grid(column=1,row=4,padx=(5,10),pady=(12,0))
proj_coluna1_text5.config(state='readonly',readonlybackground='white')

proj_coluna0_text6 = tk.Label(projeto_coluna0,text='VLAN ID',anchor='w',bg=cor_coluna_0)
proj_coluna0_text6.grid(column=0,row=5,padx=(5,10),pady=(10,0),sticky='w')

proj_coluna1_text6 = tk.Entry(projeto_coluna0,bg=cor_coluna_1,justify='left',width=50)
proj_coluna1_text6.insert(0,'')
proj_coluna1_text6.grid(column=1,row=5,padx=(5,10),pady=(13,0))
proj_coluna1_text6.config(state='readonly',readonlybackground='white')

proj_coluna0_text7 = tk.Label(projeto_coluna0,text='VLAN priority',anchor='w',bg=cor_coluna_0)
proj_coluna0_text7.grid(column=0,row=6,padx=(5,10),pady=(10,0),sticky='w')

proj_coluna1_text7 = tk.Entry(projeto_coluna0,bg=cor_coluna_1,justify='left',width=50)
proj_coluna1_text7.insert(0,'')
proj_coluna1_text7.grid(column=1,row=6,padx=(5,10),pady=(12,0))
proj_coluna1_text7.config(state='readonly',readonlybackground='white')

proj_coluna0_text8 = tk.Label(projeto_coluna0,text='Configuration revision',anchor='w',bg=cor_coluna_0)
proj_coluna0_text8.grid(column=0,row=7,padx=(5,10),pady=(10,0),sticky='w')

proj_coluna1_text8 = tk.Entry(projeto_coluna0,bg=cor_coluna_1,justify='left',width=50)
proj_coluna1_text8.insert(0,'')
proj_coluna1_text8.grid(column=1,row=7,padx=(5,10),pady=(12,0))
proj_coluna1_text8.config(state='readonly',readonlybackground='white')

proj_coluna0_text9 = tk.Label(projeto_coluna0,text='TimeAllowedtoLive',anchor='w',bg=cor_coluna_0)
proj_coluna0_text9.grid(column=0,row=8,padx=(5,10),pady=(10,0),sticky='w')

proj_coluna1_text9 = tk.Entry(projeto_coluna0,bg=cor_coluna_1,justify='left',width=50)
proj_coluna1_text9.insert(0,'')
proj_coluna1_text9.grid(column=1,row=8,padx=(5,10),pady=(12,0))
proj_coluna1_text9.config(state='readonly',readonlybackground='white')

proj_coluna0_text10 = tk.Label(projeto_coluna0,text='NumDatSetEntries',anchor='w',bg=cor_coluna_0)
proj_coluna0_text10.grid(column=0,row=9,padx=(5,10),pady=(10,5),sticky='w')

proj_coluna1_text10 = tk.Entry(projeto_coluna0,bg=cor_coluna_1,justify='left',width=50)
proj_coluna1_text10.insert(0,'')
proj_coluna1_text10.grid(column=1,row=9,padx=(5,10),pady=(12,5))
proj_coluna1_text10.config(state='readonly',readonlybackground='white')

imagem = PhotoImage(file="Icones\caution.png") 

cap_coluna0_text1 = tk.Label(capturado_coluna0,text='Control block reference',anchor='w',bg=cor_coluna_0)
cap_coluna0_text1.grid(column=0,row=0,padx=(5,10),pady=(5,0),sticky='wn')

cap_coluna1_text1 = tk.Entry(capturado_coluna0,bg=cor_coluna_1,justify='left',width=50)
cap_coluna1_text1.insert(0,'')
cap_coluna1_text1.grid(column=1,row=0,padx=(5,10),pady=(7,0),sticky='w')
cap_coluna1_text1.config(state='readonly',readonlybackground='white')

cap_coluna2_imagem1 = tk.Label(capturado_coluna0, image=imagem,bg=cor_coluna_0,anchor='w')

cap_coluna0_text2 = tk.Label(capturado_coluna0,text='Destination MAC addres',anchor='w',bg=cor_coluna_0)
cap_coluna0_text2.grid(column=0,row=1,padx=(5,10),pady=(10,0),sticky='w')

cap_coluna1_text2 = tk.Entry(capturado_coluna0,bg=cor_coluna_1,justify='left',width=50)
cap_coluna1_text2.insert(0,'')
cap_coluna1_text2.grid(column=1,row=1,padx=(5,10),pady=(10,0))
cap_coluna1_text2.config(state='readonly',readonlybackground='white')

cap_coluna2_imagem2 = tk.Label(capturado_coluna0, image=imagem,bg=cor_coluna_0,anchor='w')

cap_coluna0_text3 = tk.Label(capturado_coluna0,text='Application ID',anchor='w',bg=cor_coluna_0)
cap_coluna0_text3.grid(column=0,row=2,padx=(5,10),pady=(10,0),sticky='w')

cap_coluna1_text3 = tk.Entry(capturado_coluna0,bg=cor_coluna_1,justify='left',width=50)
cap_coluna1_text3.insert(0,'')
cap_coluna1_text3.grid(column=1,row=2,padx=(5,10),pady=(11,0))
cap_coluna1_text3.config(state='readonly',readonlybackground='white')

cap_coluna2_imagem3 = tk.Label(capturado_coluna0, image=imagem,bg=cor_coluna_0,anchor='w')

cap_coluna0_text4 = tk.Label(capturado_coluna0,text='GOOSE ID',anchor='w',bg=cor_coluna_0)
cap_coluna0_text4.grid(column=0,row=3,padx=(5,10),pady=(10,0),sticky='w')

cap_coluna1_text4 = tk.Entry(capturado_coluna0,bg=cor_coluna_1,justify='left',width=50)
cap_coluna1_text4.insert(0,'')
cap_coluna1_text4.grid(column=1,row=3,padx=(5,10),pady=(11,0))
cap_coluna1_text4.config(state='readonly',readonlybackground='white')

cap_coluna2_imagem4 = tk.Label(capturado_coluna0, image=imagem,bg=cor_coluna_0,anchor='w') 

cap_coluna0_text5 = tk.Label(capturado_coluna0,text='DataSet reference',anchor='w',bg=cor_coluna_0)
cap_coluna0_text5.grid(column=0,row=4,padx=(5,10),pady=(10,0),sticky='w')

cap_coluna1_text5 = tk.Entry(capturado_coluna0,bg=cor_coluna_1,justify='left',width=50)
cap_coluna1_text5.insert(0,'')
cap_coluna1_text5.grid(column=1,row=4,padx=(5,10),pady=(12,0))
cap_coluna1_text5.config(state='readonly',readonlybackground='white')

cap_coluna2_imagem5 = tk.Label(capturado_coluna0, image=imagem,bg=cor_coluna_0,anchor='w')

cap_coluna0_text6 = tk.Label(capturado_coluna0,text='VLAN ID',anchor='w',bg=cor_coluna_0)
cap_coluna0_text6.grid(column=0,row=5,padx=(5,10),pady=(10,0),sticky='w')

cap_coluna1_text6 = tk.Entry(capturado_coluna0,bg=cor_coluna_1,justify='left',width=50)
cap_coluna1_text6.insert(0,'')
cap_coluna1_text6.grid(column=1,row=5,padx=(5,10),pady=(13,0))
cap_coluna1_text6.config(state='readonly',readonlybackground='white')

cap_coluna2_imagem6 = tk.Label(capturado_coluna0, image=imagem,bg=cor_coluna_0,anchor='w') 

cap_coluna0_text7 = tk.Label(capturado_coluna0,text='VLAN priority',anchor='w',bg=cor_coluna_0)
cap_coluna0_text7.grid(column=0,row=6,padx=(5,10),pady=(10,0),sticky='w')

cap_coluna1_text7 = tk.Entry(capturado_coluna0,bg=cor_coluna_1,justify='left',width=50)
cap_coluna1_text7.insert(0,'')
cap_coluna1_text7.grid(column=1,row=6,padx=(5,10),pady=(12,0))
cap_coluna1_text7.config(state='readonly',readonlybackground='white')

cap_coluna2_imagem7 = tk.Label(capturado_coluna0, image=imagem,bg=cor_coluna_0,anchor='w') 

cap_coluna0_text8 = tk.Label(capturado_coluna0,text='Configuration revision',anchor='w',bg=cor_coluna_0)
cap_coluna0_text8.grid(column=0,row=7,padx=(5,10),pady=(10,0),sticky='w')

cap_coluna1_text8 = tk.Entry(capturado_coluna0,bg=cor_coluna_1,justify='left',width=50)
cap_coluna1_text8.insert(0,'')
cap_coluna1_text8.grid(column=1,row=7,padx=(5,10),pady=(12,0))
cap_coluna1_text8.config(state='readonly',readonlybackground='white')

cap_coluna2_imagem8 = tk.Label(capturado_coluna0, image=imagem,bg=cor_coluna_0,anchor='w')

cap_coluna0_text9 = tk.Label(capturado_coluna0,text='TimeAllowedtoLive',anchor='w',bg=cor_coluna_0)
cap_coluna0_text9.grid(column=0,row=8,padx=(5,10),pady=(10,0),sticky='w')

cap_coluna1_text9 = tk.Entry(capturado_coluna0,bg=cor_coluna_1,justify='left',width=50)
cap_coluna1_text9.insert(0,'')
cap_coluna1_text9.grid(column=1,row=8,padx=(5,10),pady=(12,0))
cap_coluna1_text9.config(state='readonly',readonlybackground='white')

cap_coluna2_imagem9 = tk.Label(capturado_coluna0, image=imagem,bg=cor_coluna_0,anchor='w')

cap_coluna0_text10 = tk.Label(capturado_coluna0,text='NumDatSetEntries',anchor='w',bg=cor_coluna_0)
cap_coluna0_text10.grid(column=0,row=9,padx=(5,10),pady=(10,5),sticky='w')

cap_coluna1_text10 = tk.Entry(capturado_coluna0,bg=cor_coluna_1,justify='left',width=50)
cap_coluna1_text10.insert(0,'')
cap_coluna1_text10.grid(column=1,row=9,padx=(5,10),pady=(12,5))
cap_coluna1_text10.config(state='readonly',readonlybackground='white')

cap_coluna2_imagem10 = tk.Label(capturado_coluna0, image=imagem,bg=cor_coluna_0,anchor='w')

if aux == 1:
   Lista_redes()
   oculta_ied_prop()
   mostra_imagem_atencao()
   oculta_imagem_atencao()
   aux=0

janela.mainloop()

