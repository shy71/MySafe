using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Reflection;
using System.IO;

namespace MySafe_Adapter
{
    public class cppToCsharpAdapter
    {
        const string dllPath = "Bridge DLL.dll";

        #region Get and Delete Functions
        [DllImport(dllPath, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr getFileVaultObj();
        [DllImport(dllPath, CallingConvention = CallingConvention.Cdecl)]
        public static extern void deleteFileVaultobj(ref IntPtr obj);
        #endregion

        #region Vault Functions
        [DllImport(dllPath, CallingConvention = CallingConvention.Cdecl)]
        public static extern void create_vault(IntPtr obj, string path, string master_password);
        [DllImport(dllPath, CallingConvention = CallingConvention.Cdecl)]
        public static extern void load_vault(IntPtr obj, string path, string master_password);
        [DllImport(dllPath, CallingConvention = CallingConvention.Cdecl)]
        public static extern int is_vault_open(IntPtr obj);
        [DllImport(dllPath, CallingConvention = CallingConvention.Cdecl)]
        public static extern void close_vault(IntPtr obj);
        #endregion

        #region Files Functions
        [DllImport(dllPath, CallingConvention = CallingConvention.Cdecl)]
        public static extern void encrypt_file(IntPtr obj, string path, string new_path, string file_password, bool delete_original);
        [DllImport(dllPath, CallingConvention = CallingConvention.Cdecl)]
        public static extern void decrypt_file(IntPtr obj, string path, string newpath, string file_password, bool delete_encrypted);
        [DllImport(dllPath, CallingConvention = CallingConvention.Cdecl)]
        public static extern double get_precntege_of_process(IntPtr obj);
        #endregion

        #region Othe Functions
        [DllImport(dllPath, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr GetLastFileVaultErrorMessage(IntPtr obj);
        #endregion
    }
}
