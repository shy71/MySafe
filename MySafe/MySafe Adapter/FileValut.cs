using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace MySafe_Adapter
{
    public class FileValut
    {
        IntPtr myFileValutPointer;

        public FileValut()
        {
            myFileValutPointer = cppToCsharpAdapter.makeFileValutobj();
        }
        ~FileValut()
        {
            if (myFileValutPointer != null)
                cppToCsharpAdapter.deleteFileValutobj(ref myFileValutPointer);
        }
        public void CreateValut(string path, string masterPassword)
        {
            try
            {
                cppToCsharpAdapter.create_valut(this.myFileValutPointer, path, masterPassword);
            }
            catch (SEHException)
            {
                IntPtr cString = cppToCsharpAdapter.GetLastFileValutErrorMessage(this.myFileValutPointer);
                string message = Marshal.PtrToStringAnsi(cString);
                throw new Exception(message);
            }
            catch
            {
                throw;
            }
        }
        public void LoadValut(string path, string masterPassword)
        {
            try
            {
                cppToCsharpAdapter.load_valut(this.myFileValutPointer, path, masterPassword);
            }
            catch (SEHException)
            {
                IntPtr cString = cppToCsharpAdapter.GetLastFileValutErrorMessage(this.myFileValutPointer);
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
                cppToCsharpAdapter.encrypt_file(this.myFileValutPointer, path, filePassword);
            }
            catch (SEHException)
            {
                IntPtr cString = cppToCsharpAdapter.GetLastFileValutErrorMessage(this.myFileValutPointer);
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
                cppToCsharpAdapter.decrypt_file(this.myFileValutPointer, encryptedFilePath, newPlainTextPath, filePassword);
            }
            catch (SEHException)
            {
                IntPtr cString = cppToCsharpAdapter.GetLastFileValutErrorMessage(this.myFileValutPointer);
                string message = Marshal.PtrToStringAnsi(cString);
                throw new Exception(message);
            }
            catch
            {
                throw;
            }
        }
        private void CloseValut()
        {
            try
            {
                cppToCsharpAdapter.close_valut();
            }
            catch (SEHException)
            {
                IntPtr cString = cppToCsharpAdapter.GetLastFileValutErrorMessage(this.myFileValutPointer);
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
