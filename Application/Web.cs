//////////////////////////////////////////////////
//                                              //
//   See License.txt for Licensing information  //
//                                              //
//////////////////////////////////////////////////

using System;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;

namespace WindowsForms
{
    public static class Web
    {
        public static string GetString(string url)
        {
            using (var w = new WebClient())
            {
                w.CachePolicy = new System.Net.Cache.RequestCachePolicy(System.Net.Cache.RequestCacheLevel.NoCacheNoStore);

                var stringData = string.Empty;
                try
                {
                    stringData = w.DownloadString(url);
                }
                catch (Exception)
                {
                    // ignored
                }

                return stringData;
            }
        }

        public static DateTime NistTime
        {
            get
            {
                var myHttpWebRequest = (HttpWebRequest)WebRequest.Create("http://www.microsoft.com");
                var response = myHttpWebRequest.GetResponse();
                string todaysDates = response.Headers["date"];
                DateTime dateTime = DateTime.ParseExact(todaysDates, "ddd, dd MMM yyyy HH:mm:ss 'GMT'", CultureInfo.InvariantCulture.DateTimeFormat, DateTimeStyles.AssumeUniversal);
                return dateTime;
            }
        }
    }
}