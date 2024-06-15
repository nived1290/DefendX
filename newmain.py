import sys
import os
from PyQt5.QtWidgets import QMainWindow,QApplication,QPushButton,QFileDialog
from PyQt5.QtCore import pyqtSignal,QFile,QTextStream
from os import mkdir
import io, hashlib, hmac
from Cryptodome.Cipher import AES
from os import urandom

import encryption_and_decryption
from mpui import *
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from cryptography.fernet import Fernet

class MainWindow(QMainWindow):

    def  __init__(self):
        super(MainWindow,self).__init__()
        try:
            if not os.path.exists(r'C:miniproject2'):
                os.mkdir(r'C:\miniproject2')
                os.mkdir(r'C:\miniproject2\storage')
                f=open(r'C:\miniproject2\storage\date.txt','w')
                f.close()
                f=open(r'C:\miniproject2\storage\password.txt','w')
                f.close()
        except OSError:
            pass


        self.ui=Ui_MainWindow()
        self.ui.setupUi(self)

        self.ui.icononlywidget.hide()
        self.ui.stackedWidget.setCurrentIndex(0)
        self.ui.threelinebtn.setChecked(True)
        #when a side button clicked
        self.ui.scanbtn1.clicked.connect(self.when_scanbtn_clicked)
        self.ui.vaultbtn1.clicked.connect(self.when_valutbtn_clicked)
        self.ui.updatebtn1.clicked.connect(self.when_updatebtn_clicked)
        self.ui.settingsbtn1.clicked.connect(self.when_settingsbtn_clicked)
        self.ui.updatebtn1.clicked.connect(self.when_updatebtn_clicked)
        self.ui.infobtn1.clicked.connect(self.when_infobtn_clicked)
        self.ui.scanbtn2.clicked.connect(self.when_scanbtn_clicked)
        self.ui.vaultbtn2.clicked.connect(self.when_valutbtn_clicked)
        self.ui.updatebtn2.clicked.connect(self.when_updatebtn_clicked)
        self.ui.settingsbtn2.clicked.connect(self.when_settingsbtn_clicked)
        self.ui.updatebtn2.clicked.connect(self.when_updatebtn_clicked)
        self.ui.infobtn1_2.clicked.connect(self.when_infobtn_clicked)
        #when change
        self.ui.passwordbtn.clicked.connect(self.when_passwordbtn_clicked)

        #settings new password
        self.ui.password_confirmbtn1.clicked.connect(self.passfn)

        #settings edit password
        self.ui.change_passwordbtn1.clicked.connect(self.edit_password)

        self.ui.edit_password_confimbtn.clicked.connect(self.when_changepassword_confirmbtn_clicked)

        self.ui.vallt_password_confirm.clicked.connect(self.password_vault_compare)

        #valutlock
        self.ui.vault_lock_addfilrbtn.clicked.connect(self.when_vault_lockaddfile_clicked)
        self.ui.vault_lock_retrivefilebtn.clicked.connect(self.when_vault_lock_retrivefilebtnclicked)
        self.print_listwidget_status = True


        #scab btn clicked
        self.ui.scan_button.clicked.connect(self.when_scan_button_clicked)

        if os.stat(r"C:\miniproject2\storage\password.txt").st_size!=0:
            with open(r"C:\miniproject2\storage\password.txt", 'r') as psw:
                self.main_password=psw.readline()
                print(self.main_password)
    def when_scan_button_clicked(self):
        pass

    def when_vault_lock_retrivefilebtnclicked(self):

            open_file=QFileDialog.getExistingDirectory()
            choosen_file_name=self.ui.listWidget.currentItem().text()
            index_of_text=int(self.ui.listWidget.currentRow())+1
            password='1234'
            with open(fr'C:\miniproject2\storage\{choosen_file_name.rstrip(choosen_file_name[-3:])}key', 'rb') as in_file, open(fr'C:\miniproject2\storage\{choosen_file_name.rstrip(choosen_file_name[-3:])}key', 'wb') as out_file:
                encryption_and_decryption.decrypt(in_file, out_file,password)
            # with open(fr'C:\miniproject2\storage\{choosen_file_name.rstrip(choosen_file_name[-3:])}key', 'rb') as filekey:
            #     key = filekey.read()
            # fernet = Fernet(key)
            # with open(fr'C:\miniproject2\storage\{choosen_file_name.rstrip(choosen_file_name[-3:])}txt', 'rb') as enc_file:
            #     encrypted = enc_file.read()
            # decrypted = fernet.decrypt(encrypted)
            # with open(fr'{open_file}/{choosen_file_name}', 'wb') as dec_file:
            #     dec_file.write(decrypted)
            # current_row=self.ui.listWidget.currentRow()
            # self.ui.listWidget.takeItem(current_row)
            # os.remove(fr'C:\miniproject2\storage\{choosen_file_name.rstrip(choosen_file_name[-3:])}key')
            # os.remove(fr'C:\miniproject2\storage\{choosen_file_name.rstrip(choosen_file_name[-3:])}txt')
            # with open(fr'C:\miniproject2\storage\data.txt', 'r') as data:
            #     lines=data.readlines()
            #     ptr=1
            #     with open(fr'C:\miniproject2\storage\data.txt', 'w') as delete_data:
            #         for line in lines:
            #             if ptr !=int(index_of_text):
            #                 delete_data.write(line)
            #             ptr+=1

    def when_vault_lockaddfile_clicked(self):
            self.open_file_name = QFileDialog.getOpenFileNames()
            list_openfilename = self.open_file_name[0]
            self.name_of_file = ""
            for ele in list_openfilename:
                self.name_of_file += ele
            g=self.name_of_file.split("/")
            self.abosolute_name_of_file=g[-1]

            with open(fr'C:\miniproject2\storage\data.txt','at') as self.store_data:
                self.store_data.write(f"{self.name_of_file}\n")
                self.ui.listWidget.addItem(self.abosolute_name_of_file)
            with open(r"C:\miniproject2\storage\data.txt", 'r') as fp:
                self.no_of_lines = len(fp.readlines())

            y=fr'C:\miniproject2\storage\{self.abosolute_name_of_file.rstrip(self.abosolute_name_of_file[-3:])}txt'

            # key = Fernet.generate_key()
            # with open(fr'C:\miniproject2\storage\{self.abosolute_name_of_file.rstrip(self.abosolute_name_of_file[-3:])}key', 'wb') as filekey:
            #     filekey.write(key)
            # with open(fr'C:\miniproject2\storage\{self.abosolute_name_of_file.rstrip(self.abosolute_name_of_file[-3:])}key', 'rb') as filekey:
            #     key = filekey.read()
            # fernet = Fernet(key)
            # with open(self.name_of_file, 'rb') as file:
            #     original = file.read()
            # encrypted = fernet.encrypt(original)
            # with open(y, 'wb') as encrypted_file:
            #     encrypted_file.write(encrypted)
            # os.remove(self.name_of_file)
            self.password='1234'
            with open(fr'C:\miniproject2\storage\{self.abosolute_name_of_file.rstrip(self.abosolute_name_of_file[-3:])}key', 'rb') as in_file, open(fr'C:\miniproject2\storage\{self.abosolute_name_of_file.rstrip(self.abosolute_name_of_file[-3:])}key','wb') as out_file:
                encryption_and_decryption.encrypt(in_file, out_file, self.password)




    def on_stackedwidget_currentchanged(self,index):
        btn_list=self.ui.icononlywidget.find(QPushButton) \
                    + self.ui.fullmenuwidget.findChildren(QPushButton)
        for btn in btn_list:
            if index in[4,5]:
                btn.setAutoExclusive(False)
                btn.setChecked(False)
            else:
                btn.setAutoExclusive(True)
    def password_vault_compare(self):
        password=self.ui.vault_password_linedit.text()
        if password==self.main_password:
            self.ui.stackedWidget.setCurrentIndex(7)
            self.ui.vault_password_linedit.clear()
            if self.print_listwidget_status:
                with open(fr'C:\miniproject2\storage\data.txt', 'rt') as myline:
                    count = 0
                    for line in myline:
                        count += 1
                        g = line.split("/")
                        second_name = g[-1]
                        self.ui.listWidget.addItem(second_name.strip())
                self.print_listwidget_status=False
        else:
            self.ui.vault_password_notification.setText("wrong password")
            self.ui.vault_password_linedit.clear()
    def when_scanbtn_clicked(self):
         self.ui.stackedWidget.setCurrentIndex(0)
    def when_valutbtn_clicked(self):
        self.ui.stackedWidget.setCurrentIndex(1)
    def when_settingsbtn_clicked(self):
        self.ui.stackedWidget.setCurrentIndex(3)
        self.ui.edit_password_notification.clear()
    def when_updatebtn_clicked(self):
        self.ui.stackedWidget.setCurrentIndex(2)
    def when_infobtn_clicked(self):
        self.ui.stackedWidget.setCurrentIndex(4)
    def when_passwordbtn_clicked(self):
        if os.stat(r"C:\miniproject2\storage\password.txt").st_size==0:
            self.ui.stackedWidget.setCurrentIndex(5)
            self.ui.new_passwordbar.clear()
            self.ui.password_confirmbar.clear()
            self.ui.password_notificationbtn1.clear()
        else:
            self.ui.edit_password_notification.setText("There is an exsisting password\nTry to Change The Password if you want")
    def passfn(self):
        password1=self.ui.new_passwordbar.text()
        password2=self.ui.password_confirmbar.text()
        self.ui.new_passwordbar.clear()
        self.ui.password_confirmbar.clear()
        self.ui.password_notificationbtn1.clear()

        if password1==password2:
            n = len(password2)
            hasLower = False
            hasUpper = False
            hasDigit = False
            specialChar = False
            haslenth=False
            normalChars = "abcdefghijklmnopqrstu"
            "vwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890 "
            for i in range(n):
                if password2[i].islower():
                    hasLower = True
                if password2[i].isupper():
                    hasUpper = True
                if password2[i].isdigit():
                    hasDigit = True
                if password2[i] not in normalChars:
                    specialChar = True
            if (hasLower and hasUpper and
                hasDigit and specialChar and n >= 8):
                self.ui.password_confirmbar.clear()
                self.ui.new_passwordbar.clear()
                self.ui.passwordbtn.disconnect()
                self.ui.password_notificationbtn1.clear()
                self.ui.stackedWidget.setCurrentIndex(3)
                self.ui.edit_password_notification.setText("Password has been added")
                with open(r"C:\miniproject2\storage\password.txt",'w') as psw:
                    psw.write(password2)
                self.main_password=password2
            elif ((hasLower or hasUpper) and
                  specialChar and n >= 6):
                self.ui.password_notificationbtn1.clear()
                self.ui.password_notificationbtn1.setText("Weak password")
                self.ui.new_passwordbar.clear()
                self.ui.password_confirmbar.clear()

            else:
                self.ui.password_notificationbtn1.clear()
                self.ui.password_notificationbtn1.setText("Weak password")
                self.ui.new_passwordbar.clear()
                self.ui.password_confirmbar.clear()

    def edit_password(self):
        self.ui.stackedWidget.setCurrentIndex(6)
        self.ui.edit_password_notification.clear()
        self.ui.previos_password_lineedit.clear()
        self.ui.newpassword_lineedit.clear()
        self.ui.confirm_password_lineedit.clear()

    def when_changepassword_confirmbtn_clicked(self):
        previous_password=self.ui.previos_password_lineedit.text()
        new_password1=self.ui.newpassword_lineedit.text()
        new_password2=self.ui.confirm_password_lineedit.text()
        if os.stat(r"C:\miniproject2\storage\password.txt").st_size==0:
            self.ui.edit_password_notification_2.setText("Set the password first noob")
        elif self.main_password!=previous_password:
            self.ui.edit_password_notification_2.setText("Previous passowrod is not matching")
        elif new_password1!=new_password2:
            self.ui.edit_password_notification_2.setText("Not matching")
        elif self.main_password==new_password2:
            self.ui.edit_password_notification_2.setText("Change the current password")
        else:
            if previous_password==self.main_password and new_password1==new_password2:
                n = len(new_password2)
                hasLower = False
                hasUpper = False
                hasDigit = False
                specialChar = False
                haslenth = False
                normalChars = "abcdefghijklmnopqrstu"
                "vwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890 "
                for i in range(n):
                    if new_password2[i].islower():
                        hasLower = True
                    if new_password2[i].isupper():
                        hasUpper = True
                    if new_password2[i].isdigit():
                        hasDigit = True
                    if new_password2[i] not in normalChars:
                        specialChar = True
                if (hasLower and hasUpper and
                        hasDigit and specialChar and n >= 8):
                    with open(r"C:\miniproject2\storage\password.txt", 'w') as psw:
                        psw.write(new_password2)
                    self.main_password=new_password2
                    self.ui.edit_password_notification.setText("password has been modified")
                    self.ui.stackedWidget.setCurrentIndex(3)
                elif ((hasLower or hasUpper) and
                      specialChar and n >= 6):

                    self.ui.edit_password_notification1.setText("Weak password")
                    self.ui.newpassword_lineedit.clear()
                    self.ui.confirm_password_lineedit.clear()

                else:
                    self.ui.edit_password_notification1.clear()
                    self.ui.edit_password_notification1.setText("Weak password")
                    self.ui.confirm_password_lineedit.clear()
                    self.ui.newpassword_lineedit.clear()



if __name__=="__main__":
    app=QApplication(sys.argv)
    window=MainWindow()
    window.show()
    sys.exit(app.exec_())