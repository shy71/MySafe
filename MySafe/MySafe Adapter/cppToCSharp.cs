using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Reflection;

namespace MySafe_Adapter
{
    public class cppToCsharpAdapter
    {
        const string dllPath = "Bridge DLL.dll";
        [DllImport(dllPath, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr makeFileValutobj();
        [DllImport(dllPath, CallingConvention = CallingConvention.Cdecl)]
        public static extern void create_valut(IntPtr obj, string path,string master_password);
        [DllImport(dllPath, CallingConvention = CallingConvention.Cdecl)]
        public static extern void close_valut();
        [DllImport(dllPath, CallingConvention = CallingConvention.Cdecl)]
        public static extern void load_valut(IntPtr obj, string path, string master_password);
        [DllImport(dllPath, CallingConvention = CallingConvention.Cdecl)]
        public static extern void encrypt_file(IntPtr obj, string path, string file_password);
        [DllImport(dllPath, CallingConvention = CallingConvention.Cdecl)]
        public static extern void decrypt_file(IntPtr obj, string path,string newpath, string file_password);
        [DllImport(dllPath, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr GetLastFileValutErrorMessage(IntPtr THIS);
        [DllImport(dllPath, CallingConvention = CallingConvention.Cdecl)]
        public static extern void deleteFileValutobj(ref IntPtr THIS);
    }
}
