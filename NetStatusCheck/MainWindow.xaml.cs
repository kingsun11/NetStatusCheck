using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace NetStatusCheck
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private delegate void setButtonColor(Button buttonObj, Color bgColor, string toolTipString, bool isEnabled);
        private delegate void setCheckResultLabel(Label labelObj, string labelContent, Color bgColor, string toolTipString);
        private delegate void taskEnd();
        private delegate void printLog(string printLog);
        private delegate void addListBoxItem(PortCheckItem portItem);
        private delegate void updateListBoxItem(PortCheckItem portItemObj, bool isOpened);

        private Hashtable portDescriptionSet = new Hashtable();

        private Hashtable IpAddressLabelSet = new Hashtable();
        private CancellationTokenSource ctsPing = new CancellationTokenSource();
        private CancellationTokenSource ctsScan = new CancellationTokenSource();

        private void setResultLabelDisplay(Label labelObj, string labelContent, Color bgColor, string toolTipString)
        {
            labelObj.Content = labelContent;
            labelStatus.ToolTip = toolTipString;
            labelObj.Background = new SolidColorBrush(bgColor);
            buttonCheck.IsEnabled = true;
        }

        private void setButtonBgColor(Button buttonObj, Color bgColor, string toolTipString, bool isEnabled)
        {
            buttonObj.Background = new SolidColorBrush(bgColor);
            buttonObj.ToolTip = toolTipString;
            buttonObj.IsEnabled = isEnabled;
        }

        private void pingCheckFinished()
        {
            buttonPingStop.IsEnabled = false;
            buttonPing.IsEnabled = true;
        }

        private void scanPortFinished()
        {
            buttonScanStart.IsEnabled = true;
            buttonScanCancel.IsEnabled = false;
        }

        private void printDebugLog(string logMessage)
        {
            Debug.Print(logMessage);
            //ListBoxLog.Items.Insert(0,logMessage);
            listBoxLog.Items.Add(logMessage);
            listBoxLog.ScrollIntoView(logMessage);
        }

        private void addPortItem(PortCheckItem portItem)
        {
            listBoxPortStatus.Items.Add(portItem);
        }

        private void updatePortItem(PortCheckItem portItemObj, bool isOpened)
        {
            if (isOpened)
            {
                portItemObj.Content = portItemObj.Result;
                portItemObj.ToolTip = portItemObj.Result;
                portItemObj.Background = new SolidColorBrush(Color.FromRgb(0, 240, 0));
            }
            else
            {
                listBoxPortStatus.Items.Remove(portItemObj);
            }
        }

        private void checkRemotePortAccess(string ipAddress, int portNum, Label resultLabel)
        {
            IPAddress ip = IPAddress.Parse(ipAddress);
            try
            {
                IPEndPoint point = new IPEndPoint(ip, portNum);
                using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
                {
                    socket.Connect(point);
                    socket.Close();
                    Task.Run(() =>
                    {
                        Dispatcher.Invoke(new setCheckResultLabel(setResultLabelDisplay), new object[] { labelStatus, "Success", Color.FromRgb(0, 240, 0), null });
                        Dispatcher.Invoke(new printLog(printDebugLog), new object[] { "Connect to " + point.ToString() + " Success." });
                    });
                }
            }
            catch (SocketException ex)
            {
                Task.Run(() =>
                {
                    Dispatcher.Invoke(new setCheckResultLabel(setResultLabelDisplay), new object[] { labelStatus, "Fail", Color.FromRgb(240, 0, 0), ex.Message });
                    Dispatcher.Invoke(new printLog(printDebugLog), new object[] { ex.Message });
                });
            }
            finally
            {

            }
        }

        private void pingIpAddress(string ipAddr, Button resultButton)
        {
            if (!ctsPing.IsCancellationRequested)
            {
                Ping ping = new Ping();
                PingReply pingReply = ping.Send(ipAddr);
                string logMessage = "Ping [" + ipAddr + "],";
                if (IPStatus.Success == pingReply.Status)
                {
                    int ttlVal = pingReply.Options.Ttl;
                    string toolTipsText = "TTL=" + getTTLDesc(pingReply.Options.Ttl);
                    logMessage += " " + pingReply.RoundtripTime.ToString() + "ms";
                    Task.Run(() =>
                    {
                        Dispatcher.Invoke(new setButtonColor(setButtonBgColor), new object[] { resultButton, Color.FromRgb(124, 252, 0), toolTipsText, true });
                        Dispatcher.Invoke(new printLog(printDebugLog), new object[] { logMessage });
                    });
                }
                else
                {
                    logMessage += " Time Out.";
                    Task.Run(() =>
                    {
                        Dispatcher.Invoke(new setButtonColor(setButtonBgColor), new object[] { resultButton, Color.FromRgb(255, 69, 0), null, true });
                        Dispatcher.Invoke(new printLog(printDebugLog), new object[] { logMessage });
                    });
                }
            }
            else
            {
                Task.Run(() =>
                {
                    Dispatcher.Invoke(new setButtonColor(setButtonBgColor), new object[] { resultButton, Color.FromRgb(192, 192, 192), null, true });
                });

            }
        }

        private string getTTLDesc(int ttl)
        {
            string returnText = ttl.ToString();
            switch (ttl)
            {
                case 64:
                    returnText += ", Linux OS";
                    break;
                case 128:
                    returnText += ", Windows OS";
                    break;
                case 255:
                    returnText += ", Unit OS";
                    break;
                case 59:
                    returnText += ", PLC Device";
                    break;
            }
            return returnText;
        }

        private void scanPortOpen(PortCheckItem portItem)
        {
            if (!ctsScan.IsCancellationRequested)
            {
                string ipAddress = portItem.IpAddress;
                int portNum = portItem.Port;
                string itemText = "Port [" + portNum.ToString() + "] N/A";
                IPAddress ip = IPAddress.Parse(ipAddress);
                bool isOpened = false;
                try
                {
                    IPEndPoint point = new IPEndPoint(ip, portNum);
                    using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
                    {
                        socket.Connect(point);
                        socket.Close();
                        itemText = "Port [" + portNum.ToString() + "] " + getPortDesc(portNum);
                        portItem.Result = itemText;
                        isOpened = true;
                    }
                }
                catch (SocketException ex)
                {
                    itemText = "Port [" + portNum.ToString() + "] " + ex.Message;
                    portItem.Result = itemText;
                }
                finally
                {
                    Task.Run(() => Dispatcher.Invoke(new updateListBoxItem(updatePortItem), new object[] { portItem, isOpened }));
                }
            }
            else
            {
                string itemText = "Port [" + portItem.Port.ToString() + "] Cancelled.";
                portItem.Result = itemText;
                Task.Run(() => Dispatcher.Invoke(new updateListBoxItem(updatePortItem), new object[] { portItem, false }));
            }
        }

        private string getPortDesc(int portNum)
        {
            string returnText = "Opened.";
            if (portDescriptionSet.ContainsKey(portNum))
            {
                returnText = portDescriptionSet[portNum].ToString();
            }
            return returnText;
        }

        private void initPortDescriptionSet()
        {
            portDescriptionSet = new Hashtable();
            portDescriptionSet.Add(21, "FTP Service");
            portDescriptionSet.Add(22, "SSH Service");
            portDescriptionSet.Add(23, "Telnet Service");
            portDescriptionSet.Add(80, "HTTP Service(IIS)");
            portDescriptionSet.Add(102, "Siemens PLC");
            portDescriptionSet.Add(135, "DCOM Service");
            portDescriptionSet.Add(139, "NetBIOS Session Service");
            portDescriptionSet.Add(443, "HTTS Service (TLS/SSL)");
            portDescriptionSet.Add(445, "Microsoft-DS Shares");
            portDescriptionSet.Add(515, "Printer Spooler");
            portDescriptionSet.Add(548, "Macintosh File Service");
            portDescriptionSet.Add(631, "IPP (Internet Printing Protocol)");
            portDescriptionSet.Add(2049, "NFS Service");
            portDescriptionSet.Add(3260, "iSCSI Service");
            portDescriptionSet.Add(3389, "Microsft RDP");
            portDescriptionSet.Add(5985, "Windows PowerShell Default psSession");
            portDescriptionSet.Add(9100, "Jetdirect HP Print Services");

            portDescriptionSet.Add(1433, "MS-SQL Server");
            portDescriptionSet.Add(2383, "MS-OLAP4");
            portDescriptionSet.Add(1521, "Oracle TNS Service");
            portDescriptionSet.Add(3306, "MySQL Service");
            portDescriptionSet.Add(5500, "Oracle EM Console");

            portDescriptionSet.Add(5800, "VNC (Over Http)");
            portDescriptionSet.Add(5900, "VNC (Remote Frame Buffer)");

            portDescriptionSet.Add(902, "VMware Server Console");
            portDescriptionSet.Add(912, "VMware Authorization Service");

            portDescriptionSet.Add(1688, "KMS Service");
            portDescriptionSet.Add(5040, "连接设备平台服务");
            portDescriptionSet.Add(7680, "Delivery Optimization");

            portDescriptionSet.Add(49320, "OPC UA Server");

            portDescriptionSet.Add(1883, "MQTT,MQSeries SCADA protocol");
            portDescriptionSet.Add(5672, "AMQP");
            portDescriptionSet.Add(8009, "Apache JServ协议1.3");
            portDescriptionSet.Add(8080, "Apache HTTP Service");
            portDescriptionSet.Add(8161, "Active MQ Console");

            portDescriptionSet.Add(3528, "JBoss IIOP");
            portDescriptionSet.Add(3529, "JBoss IIOP/SSL");
            portDescriptionSet.Add(9990, "JBoss Management Console");


            portDescriptionSet.Add(403, "Rockwell Alarm Historian");
            portDescriptionSet.Add(1332, "Rockwell Redundancy Services");
            portDescriptionSet.Add(3060, "RNA Directory Server");
            portDescriptionSet.Add(4241, "RSLinx Enterprise OPC");
            portDescriptionSet.Add(4243, "Rockwell Tag Server");
            portDescriptionSet.Add(4255, "Rockwell Application Services");
            portDescriptionSet.Add(5241, "Rockwell Application Services");
            portDescriptionSet.Add(6543, "Rockwell Alarm Server");
            portDescriptionSet.Add(7153, "RSLinx Enterprise OPC");
            portDescriptionSet.Add(8082, "FactoryTalk Diagnostics");
            portDescriptionSet.Add(9111, "Rockwell Alarm Server");
        }

        private void limitInputNumber(object sender, KeyEventArgs e, int maxValue)
        {
            TextBox textObj = sender as TextBox;
            if ((e.Key >= Key.D0 && e.Key <= Key.D9) || (e.Key >= Key.NumPad0 && e.Key <= Key.NumPad9))
            {
                //按下了Alt、ctrl、shift等修饰键
                if (e.KeyboardDevice.Modifiers != ModifierKeys.None)
                {
                    e.Handled = true;
                }
                else
                {
                    string InputVal = e.Key.ToString().Substring(e.Key.ToString().Length - 1);

                    int startIdx = textObj.SelectionStart;
                    int endIdx = startIdx + textObj.SelectionLength;
                    string startStr = textObj.Text.Substring(0, startIdx);
                    string endString = textObj.Text.Substring(endIdx);
                    if (long.Parse(startStr + InputVal + endString) > maxValue)
                    {
                        e.Handled = true;
                    }
                }

            }
            else if (e.Key == Key.Delete || e.Key == Key.Back || e.Key == Key.Tab || e.Key == Key.Enter ||
                e.Key == Key.Left || e.Key == Key.Right || e.Key == Key.Home || e.Key == Key.End)
            {
                // Modify Current Focus or Value.
            }
            else if (e.KeyboardDevice.Modifiers == ModifierKeys.Control && e.Key == Key.C)
            {
                // Copy Value to Clipboard.
            }
            else if (e.KeyboardDevice.Modifiers == ModifierKeys.Control && e.Key == Key.V)
            {
                // Parse Value form Clipboard.
                try
                {
                    IDataObject iData = Clipboard.GetDataObject();
                    if (iData.GetDataPresent(DataFormats.Text))
                    {
                        string InputVal = (string)iData.GetData(DataFormats.Text);
                        if (string.IsNullOrWhiteSpace(InputVal))
                        {
                            e.Handled = true;
                        }
                        else
                        {
                            const string pattern = "^[0-9]*$";
                            Regex rx = new Regex(pattern);
                            if (rx.IsMatch(InputVal))
                            {
                                int startIdx = textObj.SelectionStart;
                                int endIdx = startIdx + textObj.SelectionLength;
                                string startStr = textObj.Text.Substring(0, startIdx);
                                string endString = textObj.Text.Substring(endIdx);
                                if (long.Parse(startStr + InputVal + endString) > maxValue)
                                {
                                    e.Handled = true;
                                }
                            }
                            else
                            {
                                e.Handled = true;
                            }
                        }
                    }
                    else
                    {
                        e.Handled = true;
                    }
                }
                catch (Exception)
                {
                    e.Handled = true;
                }
            }
            else//按下了字符等其它功能键
            {
                e.Handled = true;
            }
        }

        private void textBoxSelectAll(object sender, RoutedEventArgs e)
        {
            TextBox currObj = sender as TextBox;
            currObj.SelectAll();
        }

        private void clickIPButton(object sender, RoutedEventArgs e)
        {
            Button btn = sender as Button;
            string ipAddress = textBoxIPA.Text + "." + textBoxIPB.Text + "." + textBoxIPC.Text + "." + btn.Content;
            textBoxHostIP.Text = ipAddress;
            setResultLabelDisplay(labelStatus, "", Color.FromRgb(128, 128, 128), null);
        }

        private void Window_Initialized(object sender, EventArgs e)
        {
            this.Width = 600;
            PortScanDisplay.Visibility = Visibility.Hidden;

            for (int idx = 1; idx < 255; idx++)
            {
                Button buttonIpAddress = new Button();
                buttonIpAddress.Content = idx.ToString();
                buttonIpAddress.Click += new RoutedEventHandler(clickIPButton);
                buttonIpAddress.IsEnabled = true;
                buttonIpAddress.Width = 33;
                buttonIpAddress.Height = 19;
                buttonIpAddress.Margin = new Thickness(2);
                buttonIpAddress.Padding = new Thickness(0);
                buttonIpAddress.Background = new SolidColorBrush(Color.FromRgb(192, 192, 192));
                buttonIpAddress.BorderBrush = new SolidColorBrush(Color.FromRgb(0, 0, 0));
                buttonIpAddress.BorderThickness = new Thickness(1);
                buttonIpAddress.FontSize = 12;
                buttonIpAddress.HorizontalAlignment = HorizontalAlignment.Center;
                buttonIpAddress.HorizontalContentAlignment = HorizontalAlignment.Center;
                buttonIpAddress.VerticalAlignment = VerticalAlignment.Center;
                buttonIpAddress.VerticalContentAlignment = VerticalAlignment.Center;
                ipAddressGrid.Children.Add(buttonIpAddress);
                IpAddressLabelSet.Add(buttonIpAddress.Content, buttonIpAddress);
            }
            ArrayList textObjList = new ArrayList();
            textObjList.Add(textBoxIPA);
            textObjList.Add(textBoxIPB);
            textObjList.Add(textBoxIPC);
            textObjList.Add(textBoxIPD1);
            textObjList.Add(textBoxIPD2);
            textObjList.Add(textBoxHostIP);
            textObjList.Add(textBoxPort);
            textObjList.Add(textBoxPortStart);
            textObjList.Add(textBoxPortEnd);
            foreach (TextBox textObj in textObjList)
            {
                textObj.GotFocus += new RoutedEventHandler(textBoxSelectAll);
            }

            // Get IP Address for loacal host
            try
            {
                string localIPAddress = "";
                IPHostEntry IpEntry = Dns.GetHostEntry(Dns.GetHostName());
                for (int i = 0; i < IpEntry.AddressList.Length; i++)
                {
                    if (IpEntry.AddressList[i].AddressFamily == AddressFamily.InterNetwork)
                    {
                        Dispatcher.Invoke(new printLog(printDebugLog), new object[] { "Local Host IP:" + IpEntry.AddressList[i].ToString() });
                        if (localIPAddress.Length == 0)
                        {
                            localIPAddress = IpEntry.AddressList[i].ToString();
                        }
                    }
                }
                if (localIPAddress.Length > 0)
                {
                    string[] ipArr = localIPAddress.Split('.');
                    if (ipArr.Length == 4)
                    {
                        textBoxIPA.Text = ipArr[0];
                        textBoxIPB.Text = ipArr[1];
                        textBoxIPC.Text = ipArr[2];
                        textBoxHostIP.Text = localIPAddress;
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("获取本机IP出错:" + ex.Message, "Error 错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }

            initPortDescriptionSet();
        }

        private void numberInput_254(object sender, KeyEventArgs e)
        {
            limitInputNumber(sender, e, 254);
        }

        private void numberInput_65535(object sender, KeyEventArgs e)
        {
            limitInputNumber(sender, e, 65535);
        }

        private void buttonPing_Click(object sender, RoutedEventArgs e)
        {
            for (int idx = 1; idx < 255; idx++)
            {
                Button buttonObj = IpAddressLabelSet[idx.ToString()] as Button;
                setButtonBgColor(buttonObj, Color.FromRgb(192, 192, 192), null, true);
            }
            int startVal = int.Parse(textBoxIPD1.Text);
            int endVal = int.Parse(textBoxIPD2.Text) + 1;
            if (endVal > startVal)
            {
                buttonPingStop.IsEnabled = true;
                buttonPing.IsEnabled = false;
                ctsPing = new CancellationTokenSource();
                TaskFactory tf = new TaskFactory();
                List<Task> pingTaskArray = new List<Task>();
                for (int idx = startVal; idx < endVal; idx++)
                {
                    Button buttonObj = IpAddressLabelSet[idx.ToString()] as Button;
                    setButtonBgColor(buttonObj, Color.FromRgb(255, 255, 0), "Checking...", false);
                    string ipAddress = textBoxIPA.Text + "." + textBoxIPB.Text + "." + textBoxIPC.Text + "." + idx.ToString();
                    pingTaskArray.Add(tf.StartNew(() => pingIpAddress(ipAddress, buttonObj)));
                }
                tf.ContinueWhenAll(pingTaskArray.ToArray(), task => Dispatcher.Invoke(new taskEnd(pingCheckFinished), new object[] { }), CancellationToken.None);
            }
            else
            {
                MessageBox.Show("IP地址范围错误", "Error Message", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void buttonPingStop_Click(object sender, RoutedEventArgs e)
        {
            buttonPingStop.IsEnabled = false;
            ctsPing.Cancel();
        }

        private void buttonCheck_Click(object sender, RoutedEventArgs e)
        {
            setResultLabelDisplay(labelStatus, "Checking", Color.FromRgb(255, 255, 0), null);
            buttonCheck.IsEnabled = false;
            string ipAddress = textBoxHostIP.Text;
            int portNum = int.Parse(textBoxPort.Text);
            Task checkTask = Task.Run(() => checkRemotePortAccess(ipAddress, portNum, labelStatus));
        }

        private void buttonShowScan_Click(object sender, RoutedEventArgs e)
        {
            if (PortScanDisplay.Visibility == Visibility.Visible)
            {
                this.Width = 600;
                PortScanDisplay.Visibility = Visibility.Hidden;
            }
            else
            {
                this.Width = 900;
                PortScanDisplay.Visibility = Visibility.Visible;
            }
        }

        private void buttonScanStart_Click(object sender, RoutedEventArgs e)
        {
            listBoxPortStatus.Items.Clear();
            string ipAddr = textBoxHostIP.Text;
            //Ping ping = new Ping();
            //PingReply pingReply = ping.Send(ipAddr);
            //if (IPStatus.Success == pingReply.Status)
            //{
                buttonScanStart.IsEnabled = false;
                buttonScanCancel.IsEnabled = true;
                List<PortCheckItem> portCheckLabelList = new List<PortCheckItem>();
                int portNumStart = int.Parse(textBoxPortStart.Text);
                int portNumEnd = int.Parse(textBoxPortEnd.Text) + 1;
                for (int portNum = portNumStart; portNum < portNumEnd; portNum++)
                {
                    PortCheckItem portLabelObj = new PortCheckItem(ipAddr, portNum);
                    portCheckLabelList.Add(portLabelObj);
                }
                Task.Factory.StartNew(() =>
                {
                    ctsScan = new CancellationTokenSource();
                    TaskFactory tf = new TaskFactory();
                    List<Task> scanTaskArray = new List<Task>();
                    foreach (PortCheckItem portObj in portCheckLabelList)
                    {
                        Dispatcher.Invoke(new addListBoxItem(addPortItem), new object[] { portObj });
                        scanTaskArray.Add(Task.Run(() => scanPortOpen(portObj)));
                    }
                    tf.ContinueWhenAll(scanTaskArray.ToArray(), task => Dispatcher.Invoke(new taskEnd(scanPortFinished), new object[] { }), CancellationToken.None);

                });
            //}
            //else
            //{
            //    listBoxPortStatus.Items.Add("Host [" + ipAddr + "] not available.");
            //}
        }

        private void buttonScanCancel_Click(object sender, RoutedEventArgs e)
        {
            buttonScanCancel.IsEnabled = false;
            ctsScan.Cancel();
        }

        private class PortCheckItem : Label
        {
            private string _ipAddress = string.Empty;
            private int _portNum = 0;
            private string _result = string.Empty;
            public PortCheckItem(string ipAddress, int portNum)
            {
                _ipAddress = ipAddress;
                _portNum = portNum;
                this.Content = "Port [" + _portNum.ToString() + "] checking...";
                this.Background = new SolidColorBrush(Color.FromRgb(255, 255, 0));

                this.Height = 30;
                this.Width = 245;

                this.Margin = new Thickness(0);
                this.Padding = new Thickness(5, 0, 0, 0);
                this.BorderBrush = new SolidColorBrush(Color.FromRgb(0, 0, 0));
                this.BorderThickness = new Thickness(1);
                this.FontSize = 12;
                this.HorizontalAlignment = HorizontalAlignment.Center;
                this.HorizontalContentAlignment = HorizontalAlignment.Left;
                this.VerticalAlignment = VerticalAlignment.Center;
                this.VerticalContentAlignment = VerticalAlignment.Center;
            }
            public string IpAddress
            {
                get
                {
                    return this._ipAddress;
                }
                set
                {
                    this._ipAddress = value;
                }
            }
            public int Port
            {
                get
                {
                    return this._portNum;
                }
                set
                {
                    this._portNum = value;
                }
            }
            public string Result
            {
                get
                {
                    return this._result;
                }
                set
                {
                    this._result = value;
                }
            }
        }

    }
}