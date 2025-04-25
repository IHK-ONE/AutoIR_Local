# -*- coding: UTF-8 -*-
from plugins.HijackAnalysis import *
from plugins.UserAnalysis import *
from plugins.ProcAnalysis import *
from plugins.FileAnalysis import *
from plugins.NetAnalysis import *
from plugins.BackdoorAnalysis import *
from plugins.LogAnalysis import *
from plugins.RookitUpload import *


def main():
    HijackAnalysis()
    UserAnalysis()
    ProcAnalysis()
    NetAnalysis()
    FileAnalysis()
    BackdoorAnalysis()
    LogAnalysis()
    RookitExtract()
