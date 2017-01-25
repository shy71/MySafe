using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace MySafe_Adapter
{
    public class FileVault
    {
        IntPtr myFileVaultPointer;
        private string fileName;

        public string FileName
        {
            get { return fileName; }
        }
        private string filePath;

        public string FilePath
        {
            get { return filePath; }
        }
        public FileVault()
        {
            myFileVaultPointer = cppToCsharpAdapter.makeFileValutobj();
        }
        ~FileVault()
        {
            if (myFileVaultPointer != null)
                cppToCsharpAdapter.deleteFileValutobj(ref myFileVaultPointer);
        }
        public void CreateVault(string path, string masterPassword)
        {
            try
            {
                if (isVaultOpen())
                    throw new Exception("There is an already open vault, close it before opening a new one");
                    cppToCsharpAdapter.create_valut(this.myFileVaultPointer, path, masterPassword);
                if(isVaultOpen())
                {
                    fileName = Path.GetFileName(path);
                    filePath = path;
                }
            }
            catch (SEHException)
            {
                IntPtr cString = cppToCsharpAdapter.GetLastFileValutErrorMessage(this.myFileVaultPointer);
                string message = Marshal.PtrToStringAnsi(cString);
                throw new Exception(message);
            }
            catch
            {
                throw;
            }
        }
        public void LoadVault(string path, string masterPassword)
        {
            try
            {

                if (isVaultOpen())
                    throw new Exception("There is an already open vault, close it before opening a new one");
                cppToCsharpAdapter.load_valut(this.myFileVaultPointer, path, masterPassword);
                if (isVaultOpen())
                {
                    fileName = Path.GetFileName(path);
                    filePath = path;
                }
            }
            catch (SEHException)
            {
                IntPtr cString = cppToCsharpAdapter.GetLastFileValutErrorMessage(this.myFileVaultPointer);
                string message = Marshal.PtrToStringAnsi(cString);
                throw new Exception(message);
            }
            catch
            {
                throw;
            }
        }
        public void EncryptFile(string path,string newPath, string filePassword)
        {
            try
            {
                cppToCsharpAdapter.encrypt_file(this.myFileVaultPointer, path, filePassword);
            }
            catch (SEHException)
            {
                IntPtr cString = cppToCsharpAdapter.GetLastFileValutErrorMessage(this.myFileVaultPointer);
                string message = Marshal.PtrToStringAnsi(cString);
                throw new Exception(message);
            }
            catch
            {
                throw;
            }
        }
        public void DecryptFile(string encryptedFilePath,string newPlainTextPath, string filePassword)
        {
            try
            {
                cppToCsharpAdapter.decrypt_file(this.myFileVaultPointer, encryptedFilePath, newPlainTextPath, filePassword);
            }
            catch (SEHException)
            {
                IntPtr cString = cppToCsharpAdapter.GetLastFileValutErrorMessage(this.myFileVaultPointer);
                string message = Marshal.PtrToStringAnsi(cString);
                throw new Exception(message);
            }
            catch
            {
                throw;
            }
        }
        public void CloseVault()
        {
            try
            {
                cppToCsharpAdapter.close_valut();
                if(isVaultOpen())
                {
                    fileName = "";
                    filePath = "";
                }
            }
            catch (SEHException)
            {
                IntPtr cString = cppToCsharpAdapter.GetLastFileValutErrorMessage(this.myFileVaultPointer);
                string message = Marshal.PtrToStringAnsi(cString);
                throw new Exception(message);
            }
            catch
            {
                throw;
            }
        }
        public bool isVaultOpen()
        {
            try
            {
               return (cppToCsharpAdapter.is_vault_open(this.myFileVaultPointer)==1);
            }
            catch (SEHException)
            {
                IntPtr cString = cppToCsharpAdapter.GetLastFileValutErrorMessage(this.myFileVaultPointer);
                string message = Marshal.PtrToStringAnsi(cString);
                throw new Exception(message);
            }
            catch
            {
                throw;
            }
        }
    }
}
