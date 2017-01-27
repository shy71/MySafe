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
            myFileVaultPointer = cppToCsharpAdapter.getFileVaultObj();
        }
        ~FileVault()
        {
            if (myFileVaultPointer != null)
                cppToCsharpAdapter.deleteFileVaultobj(ref myFileVaultPointer);
        }
        public void CreateVault(string path, string masterPassword)
        {
            try
            {
                if (path.Length > 250)
                    throw new Exception("Path length is to long! Max 250 characters");
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
                IntPtr cString = cppToCsharpAdapter.GetLastFileVaultErrorMessage(this.myFileVaultPointer);
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
                if (path.Length > 250)
                    throw new Exception("Path length is to long! Max 250 characters");
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
                IntPtr cString = cppToCsharpAdapter.GetLastFileVaultErrorMessage(this.myFileVaultPointer);
                string message = Marshal.PtrToStringAnsi(cString);
                throw new Exception(message);
            }
            catch
            {
                throw;
            }
        }
        public void EncryptFile(string path,string newPath, string filePassword,bool deleteOriginal)
        {
            try
            {
                if (path.Length > 250 || newPath.Length > 250)
                    throw new Exception("Path length is to long! Max 250 characters");       
                cppToCsharpAdapter.encrypt_file(this.myFileVaultPointer, path,newPath, filePassword, deleteOriginal);
            }
            catch (SEHException)
            {
                IntPtr cString = cppToCsharpAdapter.GetLastFileVaultErrorMessage(this.myFileVaultPointer);
                string message = Marshal.PtrToStringAnsi(cString);
                throw new Exception(message);
            }
            catch
            {
                throw;
            }
        }
        public void DecryptFile(string encryptedFilePath,string newPlainTextPath, string filePassword, bool deleteEncrypted)
        {
            try
            {
                if (encryptedFilePath.Length > 250 || newPlainTextPath.Length > 250)
                    throw new Exception("Path length is to long! Max 250 characters");
                cppToCsharpAdapter.decrypt_file(this.myFileVaultPointer, encryptedFilePath, newPlainTextPath, filePassword,deleteEncrypted);
            }
            catch (SEHException)
            {
                IntPtr cString = cppToCsharpAdapter.GetLastFileVaultErrorMessage(this.myFileVaultPointer);
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
                cppToCsharpAdapter.close_valut(this.myFileVaultPointer);
                if (!isVaultOpen())
                {
                    fileName = "";
                    filePath = "";
                }
                else
                    throw new Exception("Error: Vault wasn't closed!");
            }
            catch (SEHException)
            {
                IntPtr cString = cppToCsharpAdapter.GetLastFileVaultErrorMessage(this.myFileVaultPointer);
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
                IntPtr cString = cppToCsharpAdapter.GetLastFileVaultErrorMessage(this.myFileVaultPointer);
                string message = Marshal.PtrToStringAnsi(cString);
                throw new Exception(message);
            }
            catch
            {
                throw;
            }
        }
        public double GetPrecntegeOfProcess()
        {
            try
            {
                return cppToCsharpAdapter.get_precntege_of_process(this.myFileVaultPointer);
            }
            catch (SEHException)
            {
                IntPtr cString = cppToCsharpAdapter.GetLastFileVaultErrorMessage(this.myFileVaultPointer);
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
