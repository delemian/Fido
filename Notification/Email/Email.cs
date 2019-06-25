using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Fido_Main.Notification.Email
{
    class Email
    {
        string sTo { get; set; }
        string sCC { get; set; }
        string sFrom { get; set; }
        string sSubject { get; set; }
        string sBody { get; set; }
        List<string> lGaugeAttachment { get; set; }
        string sEmailAttachment { get; set; }

        }
}
