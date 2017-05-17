"""
    Name:           oleNativeCarve.py
    Author:         Alexander Hanel
    Version:        1.2
    Date:           20170516
    Description:    Extracts embedded objects from olenative records.
                    The extracted object will be saved as SHA256.bin with a corresponding file named
                    SHA256.json that contains information about the extracted
    Example:

C:\Users\Admin\Desktop\examples>oleNativeCarve.py
520c8eabb1a5f0895cbe056dcf5d568c090c66100f15ccef5e55c4b3fd017684 not a valid zip
    ..
03/14/2017  10:06 AM           581,723 c5d19edc4187c936682e5ab45a2cb99724d447a1d68f914fce5ccfdd25c8e53f.bin
03/14/2017  10:06 AM               446 c5d19edc4187c936682e5ab45a2cb99724d447a1d68f914fce5ccfdd25c8e53f.json
03/10/2017  02:31 PM           580,359 e635400d56049f8ee3f26e372f87c90816c48f73d114cab1bef78a5ed2a1df3a
03/14/2017  10:05 AM             5,160 oleNativeCarve.py

Contents of SHA256.json

    {"native_data_size": 581723, "parent_sha256": "e635400d56049f8ee3f26e372f87c90816c48f73d114cab1bef78a5ed2a1df3a",
    "flags1": 2, "flags2": 0, "unknown": 0, "label": "www.revenueads.com", "unknown2": 3, "unknown3": null,
    "command": "C:\\Users\\Admin\\AppData\\Local\\Temp\\www.revenueads.com",
    "sha256": "c5d19edc4187c936682e5ab45a2cb99724d447a1d68f914fce5ccfdd25c8e53f",
    "file_path": "C:\\Users\\Admin\\Desktop\\www.revenueads.com", "size": 582085}

"""

import hashlib
import os
import sys
import json
import hashlib
import olefile
import shutil
import struct
import tempfile
import zipfile


class olenative():
    def __init__(self, data):
        self.success = False
        self.error = ""
        self.size = int
        self.flags1 = None
        self.label = str
        self.file_path = str
        self.flags2 = None
        self.unknown = None
        self.unknown2 = None
        self.command = str
        self.native_data_size = int
        self.native_data = str
        self.unknown3 = None
        self.sha256 = None
        self.parent_sha256 = None
        self.parse_ole_native(data)

    def return_dict(self):
        """populate temp dict that stores configurations"""
        temp_dict = {}
        temp_dict["size"] = self.size
        temp_dict["flags1"] = self.flags1
        temp_dict["label"] = self.label
        temp_dict["file_path"] = self.file_path
        temp_dict["flags2"] = self.flags2
        temp_dict["unknown"] = self.unknown
        temp_dict["unknown2"] = self.unknown2
        temp_dict["command"] = self.command
        temp_dict["native_data_size"] = self.native_data_size
        # native data is saved as binary file of the sha256 name
        temp_dict["unknown3"] = self.unknown3
        temp_dict["sha256"] = self.sha256
        temp_dict["parent_sha256"] = self.parent_sha256
        return temp_dict

    def parse_ole_native(self, data):
        """ parses olenative structure"""
        try:
            # get size
            self.size = struct.unpack('<L', data[0:4])[0]
            data = data[4:]
            # get flag1, typically a hardcoded value of 02 00
            self.flags1 = struct.unpack('<H', data[0:2])[0]
            data = data[2:]
            # get label aka name of the embedded file. label is a string of unknown length
            self.label = data[:data.find('\0')]
            # calculate length of string label1
            data = data[len(self.label) + 1:]
            # get file name
            self.file_path = data[:data.find('\0')]
            data = data[len(self.file_path):]
            # get flag2
            self.flags2 = struct.unpack('<H', data[0:2])[0]
            data = data[2:]
            self.unknown = struct.unpack('<B', data[0:1])[0]
            data = data[1:]
            self.unknown2 = struct.unpack('<B', data[0:1])[0]
            # skipping four bytes not sure what they are
            data = data[6:]
            self.command = data[:data.find('\0')]
            data = data[len(self.command) + 1:]
            self.native_data_size = struct.unpack('<L', data[0:4])[0]
            data = data[4:]
            self.native_data = data[:self.native_data_size]
            sha = hashlib.sha256()
            sha.update(self.native_data)
            self.sha256 = sha.hexdigest()
        except Exception as e:
            self.success = False
            self.error = e 
            return 
        self.success = True 


def carve_ole_native(file_path, debug=True):
    """Carves olenative embedded objects, saves a SHA256.bin & SHA256.json returns file names"""
    hash_sha256 = hashlib.sha256()
    # read file into chunks
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    dir_path = tempfile.mkdtemp()
    try:
        with zipfile.ZipFile(file_path, "r") as zip_ref:
            zip_ref.extractall(dir_path)
    except:
        if debug:
            print "%s not a valid zip" % (hash_sha256.hexdigest())
        return

    out_files = []
    for root, dirs, files in os.walk(dir_path):
        for name in files:
            # Each OLEObject object represents an ActiveX control or a linked or embedded OLE object.
            # can be "oleObjectX" where is X is an integer value
            # location of oleObjectX /<application/embeddings/
            if "oleObject" in name:
                oledir = tempfile.mkdtemp()
                olepath = os.path.join(root, name)
                try:
                    ole = olefile.OleFileIO(olepath)
                except:
                    if debug:
                        print "invalid OLE structure"
                    continue
                # An Ole10Native record which is wrapped around certain binary files being embedded in OLE2 documents.
                if ole.exists('\x01Ole10Native'):
                    ole_native = ole.openstream('\x01Ole10Native').read()
                    # check for empty olenative streams
                    if len(ole_native) == 0:
                        continue
                    # parse olenative stream 
                    ole_class = olenative(ole_native)
                    if ole_class.success:
                        ole_class.parent_sha256 = hash_sha256.hexdigest()
                        # write binary data
                        name_bin = ole_class.sha256 + ".bin"
                        root_path = os.path.dirname(os.path.abspath(file_path))
                        path_name_bin = os.path.join(root_path, name_bin)
                        with open(path_name_bin, "wb") as outfile:
                            outfile.write(ole_class.native_data)
                        # write JSON
                        name_json = ole_class.sha256 + ".json"  
                        path_name_json = os.path.join(root_path, name_json)
                        with open(path_name_json, "wb") as jsonout:
                            json.dump(ole_class.return_dict(), jsonout, encoding='latin1')
                        out_files.append((path_name_bin, path_name_json))
                        shutil.rmtree(oledir)
                    else:
                        if debug:
                            print "Error Could not parse OleNative %s" % (hash_sha256.hexdigest())
                            print "Path: %s" % olepath
                else:
                    if debug:
                        print "%s \x01Ole10Native is not present" % (hash_sha256.hexdigest())
                    continue

    # deleting oledir path threw errors due to an open handle
    try:
        shutil.rmtree(dir_path)
    except Exception as e:
        if debug:
            print "Delete Folder Error: %s " % e

    return out_files