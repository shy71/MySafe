using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace MySafe_Adapter
{
    public class FileVault
    {
        IntPtr myFileVaultPointer;

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
                cppToCsharpAdapter.create_valut(this.myFileVaultPointer, path, masterPassword);
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
                cppToCsharpAdapter.load_valut(this.myFileVaultPointer, path, masterPassword);
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
        public void EncryptFile(string path, string filePassword)
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
        private void CloseVault()
        {
            try
            {
                cppToCsharpAdapter.close_valut();
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
