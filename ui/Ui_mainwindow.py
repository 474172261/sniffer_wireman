from PyQt4 import uic
from PyQt4 import QtGui
from PyQt4 import QtCore
from wireman import *
import threading

(Ui_MyFormClass, QMainWindow) = uic.loadUiType('mainwindow.ui')

class DetailModel(QtCore.QAbstractListModel):
    def __init__(self,data=[],parent=None):
        QtCore.QAbstractListModel.__init__(self,parent)
        self._data=data
    
    def rowCount(self,parent):
        return len(self._data)

    def data(self,index,role):
        if role==QtCore.Qt.DisplayRole:
            return self._data[index.row()]
            

class CapUIAction(threading.Thread):
    def __init__(self,cap, packet_list):
        threading.Thread.__init__(self)
        self.packet_list=packet_list
        self.cap=cap
        self.RUNNING=True
        self.packet_heads=[]
        self.packet_datas=[]
        self.filters=[]
        self.flag=False
    
    def initList(self):
        while self.packet_list.rowCount()>0:
            self.packet_list.removeRow(0)
            
    def setFilter(self, filters):
        self.filters=filters
        self.flag=True
    
    def stop(self):
        self.RUNNING=False
        
    def run(self):
        print 'Reading start'
        self.initList()
        while self.RUNNING:
            #print 'looping'
            if self.flag:
                self.initList()
                for i in self.packet_heads:
                    self.addRow(i)
                self.flag=False
            if self.cap.packet_heads!=[] and self.cap.isAlive():
                first_head=self.cap.getFirstHead()
                self.packet_heads.append(first_head)
                self.cap.removeFirstHead()
                first_data=self.cap.getFirstData()
                self.packet_datas.append(first_data)
                self.cap.removeFirstData()
                self.addRow(first_head)
            else:
                if self.cap.isAlive():
                    if self.cap.going_to_terminate:
                        self.cap.stop()
                time.sleep(0.01)
            
        print 'Reading Quit' 
        
    def addRow(self, packet):
        info=''
        num=str(packet[0][1]['Frame Number'])
        time=packet[0][1]['Arrive Time']
        #if it's arp
        if packet[2][1].has_key('Source'):
            src=packet[2][1]['Source']
        else:
            src=packet[2][1]['Sender Mac']
        if packet[2][1].has_key('Destination'):
            dst= packet[2][1]['Destination']
        else:
            dst=packet[2][1]['Target Mac']
            if dst=='00:00:00:00:00:00':
                dst='Bordcast'
                info+='Who is %s? Tell %s'%(packet[2][1]['Target IP'], packet[2][1]['Sender IP'])
            else:
                info+='%s is at %s'%(packet[2][1]['Sender IP'], packet[2][1]['Sender Mac'])
        pro=packet[2][1]['Protocol']
        length=str(packet[0][1]['Frame Length'])
        if pro=='TCP':
            info+=str(packet[3][1]['Source port'])+'->'+str(packet[3][1]['Destination port'])
            if packet[3][1]['SYN']==1:
                info+=' SYN:1,'
            if packet[3][1]['ACK']==1:
                info+=' ACK:1'
            if packet[3][1]['RST']==1:
                info+=' RST:1'
            if packet[3][1]['PSH']==1:
                info+=' PSH:1'
            if packet[3][1]["Reserved"]==1:
                info+='Res:1'
            if packet[3][1]["NS"]==1:
                info+='NS:1'
            if packet[3][1]["CWR"]==1:
                info+='CWR:1'
            if packet[3][1]["ECE"]==1:
                info+='ECE:1'
            if packet[3][1]["URG"]==1:
                info+='URG:1'
            if packet[3][1]["FIN"]==1:
                info+='FIN:1'
        dic={
            'No':num, 
            'time':time,
            'src':src, 
            'dst':dst, 
            'proto':pro, 
            'len':length, 
            'info':info, 
          }
        if self.filters!=[]:
            for filter in self.filters:
                if filter[1]=='=':
                    if dic[filter[0]]==filter[2]:
                        continue
                    else:
                        return
                elif filter[1]=='>':
                    if int(dic[filter[0]], 10)>filter[2]:
                        continue
                    else:
                        return
                elif filter[1]=='<':
                    if int(dic[filter[0]], 10)<filter[2]:
                        continue
                    else:
                        return
                elif filter[1]=='-':
                    if dic[filter[1]].index(filter[2]):
                        continue
                    else:
                        return
                else:
                    break
        rowposition=self.packet_list.rowCount()
        self.packet_list.insertRow(rowposition)
        self.packet_list.setItem(rowposition, 0, QtGui.QTableWidgetItem(dic['No']))
        self.packet_list.setItem(rowposition, 1, QtGui.QTableWidgetItem(dic['time']))
        self.packet_list.setItem(rowposition, 2, QtGui.QTableWidgetItem(dic['src']))
        self.packet_list.setItem(rowposition, 3, QtGui.QTableWidgetItem(dic['dst']))
        self.packet_list.setItem(rowposition, 4, QtGui.QTableWidgetItem(dic['proto']))
        self.packet_list.setItem(rowposition, 5, QtGui.QTableWidgetItem(dic['len']))
        self.packet_list.setItem(rowposition, 6, QtGui.QTableWidgetItem(dic['info']))
    
    def getPackethead(self, select):
        return self.packet_heads[select]
    
    def getPacketdata(self, select):
        return self.packet_datas[select]

class MainWindowClass (QMainWindow):
    def __init__ (self, *args):
        apply(QMainWindow.__init__, (self, ) + args)
        self.ui = Ui_MyFormClass()
        self.ui.setupUi(self)
        self.init_UI()
        self.dev_choice=[]
        self.cap_filter=''
        self.devlist=[]
        self.cap=None
        self.action=None
        self.open_file=''
        self.dump_file=''


    def init_UI(self):
        #button action 
        self.ui.start_button.clicked.connect(self.startAction)
        self.ui.stop_button.clicked.connect(self.stopAction)
        self.ui.apply_button.clicked.connect(self.applyAction)
        self.ui.device_button.clicked.connect(self.deviceAction)
        #packet_list
        self.ui.packet_list.setColumnCount(7)
        header=['No.', 'time','src', 'dst', 'proto', 'length', 'info']
        self.ui.packet_list.setHorizontalHeaderLabels(header)
        self.ui.packet_list.clicked.connect(self.itemDetails)
        ##MainWindow.connect(self.packet_list.horizontalHeader(), QtCore.SIGNAL("sectionclicked()"), self.itemDetails)
        #packet_details
        header=QtGui.QTreeWidgetItem(["Header", "value"])
        self.ui.packet_details.setHeaderItem(header)
        #menu action
            #open file
        self.ui.actionOpen_file.setShortcut('Ctrl+O')
        self.ui.actionOpen_file.triggered.connect(self.openFile)
            #dump file
        self.ui.actionSave.setShortcut('Ctrl+s')
        self.ui.actionSave.triggered.connect(self.dumpFile)

    def applyAction(self):
        filters=str(self.ui.filters.text())
        filters=filters.split()
        filter_list=[]
        for filter in filters:
            if filter.find('=')!=-1:
                opindex=filter.find('=')
                left=filter[:opindex]
                right=filter[opindex+1:]
                op='='
                filter_list.append((left,op,right))
            elif filter.find('>')!=-1:
                opindex=filter.find('>')
                left=filter[:opindex]
                right=int(filter[opindex+1:], 10)
                op='>'
                filter_list.append((left,op,right))
            elif filter.find('<')!=-1:
                opindex=filter.find('<')
                left=filter[:opindex]
                right=int(filter[opindex+1:], 10)
                op='<'
                filter_list.append((left,op,right))
            elif filter.find('-')!=-1:
                opindex=filter.find('-')
                left=filter[:opindex]
                right=filter[opindex+1:]
                op='-'
                filter_list.append((left,op,right))
        print filter_list
        if self.action!=None:
            self.action.setFilter(filter_list)
    
    def deviceAction(self):
        self.open_file=''
        self.devlist=getAllDevs()
        devlists=[]
        for i in range(len(self.devlist)/2):
            devlists.append(self.devlist[i*2+1])
        self.model=DetailModel(devlists)
        self.ui.device_list.setModel(self.model)
        self.ui.device_list.clicked.connect(self.on_device_clicked)
        
    def on_device_clicked(self, index):
        self.dev_choice=[self.devlist[index.row()*2], self.devlist[index.row()*2+1]]
        
    def startAction(self):
        if self.dev_choice==[] and self.open_file=='':
            self.ui.filters.clear()
            self.ui.filters.setText('Please select a device or file first')
            return False
        if self.cap!=None:
            if self.cap.isAlive():
                self.cap.stop()
            self.action.stop()
        self.cap=Capture()
        if self.open_file=='':
            self.cap.setDev(self.dev_choice)
        else:
            self.cap.setReadFile(self.open_file)
        self.cap.setMaxpacets(10000)
        self.cap.start()
        self.action=CapUIAction(self.cap, self.ui.packet_list)
        self.action.start()
    
    def stopAction(self):
        if self.cap!=None and self.cap.isAlive():
            print 'stop'
            self.cap.stop()
        #self.action.stop()
    
    def itemDetails(self,index):
        self.ui.packet_details.clear()
        select=self.ui.packet_list.item(index.row(), 0).text()
        select=int(str(select), 10)
        packet_head=self.action.getPackethead(select)
        packet_data=self.action.getPacketdata(select)
        if packet_head==[]:
            print 'wrong packet_head'
            return 
        for parent in packet_head:
            pitem=QtGui.QTreeWidgetItem(self.ui.packet_details, [parent[0]])
            for child in parent[1]:
                temp=parent[1][child]
                if type(temp)!=str:
                    QtGui.QTreeWidgetItem(pitem, [child,str(temp)])
                else:
                    QtGui.QTreeWidgetItem(pitem, [child,temp])
        data=[]
        for i in packet_data:
            if "'"+i+"'"!=`i`:
                data.append('.')
                continue
            data.append(i)
        self.ui.dataview.setPlainText(''.join(data))
        
        
    def openFile(self):
        self.open_file=str(QtGui.QFileDialog.getOpenFileName())

    def dumpFile(self):
        dump=str(QtGui.QFileDialog.getOpenFileName())
        if self.cap.isAlive():
            self.cap.stop()
        dst=open(dump,'wb')
        with open('temp','rb') as src:
            data=src.read()
            while data:
                dst.write(data)
                data=src.read()
        print 'dump done'

if __name__ == "__main__":

    import sys
    app = app = QtGui.QApplication(sys.argv)
    form = MainWindowClass()
    form.show()
    app.exec_()