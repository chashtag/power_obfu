#/usr/bin/env python
import logging
import sys
import os
import logging.handlers
class Logger(object):
    def __init__(self, consolefh=sys.stdout, logtofile=True, logpath=None, level=logging.INFO):
        logging.getLogger("requests").setLevel(logging.ERROR)
        BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(8)
        RESET_SEQ, COLOR_SEQ, BOLD_SEQ= ("\033[0m","\033[1;%dm","\033[1m")
        COLORS = {'WARNING': YELLOW,'INFO': GREEN,'DEBUG': BLUE,'CRITICAL': MAGENTA,'ERROR': RED}
        class ColoredFormatter(logging.Formatter):
            def __init__(self, msg, use_color = True):
                logging.Formatter.__init__(self, msg)
                self.use_color = use_color

            def format(self, record):
                levelname = record.levelname
                if self.use_color and levelname in COLORS:
                    levelname_color = COLOR_SEQ % (30 + COLORS[levelname]) + levelname + RESET_SEQ
                    record.levelname = levelname_color
                return logging.Formatter.format(self, record)
        COLOR_FORMAT = "\033[1m%(levelname)-19s\033[0m : %(message)s"
        color_formatter = ColoredFormatter(COLOR_FORMAT)
        self.log = logging.getLogger("")
        self.log.setLevel(level)
        console = logging.StreamHandler(consolefh)
        console.setLevel(level)
        console.setFormatter(color_formatter)
        self.log.addHandler(console)
        if not logpath:
            if os.geteuid():
                _logpath = '{0}.log'
            else:
                _logpath = '/var/log/{0}.log'
        else:
            _logpath = logpath
        if logtofile:
            formatter = logging.Formatter('%(levelname)s: [%(asctime)s] -- %(message)s')
            fh = logging.handlers.RotatingFileHandler(_logpath.format('Power_Obfu.log'), maxBytes=10485760, backupCount=5)
            fh.setLevel(level)
            fh.setFormatter(formatter)
            self.log.addHandler(fh)
        #self.log.info('Started {0}'.format(os.path.basename(__name__)))
        
    def error(self, msg):
        return self.log.error(msg)

    def info(self, msg):
        return self.log.info(msg)

    def warn(self, msg):
        return self.log.warn(msg)

    def debug(self, msg):
        return self.log.debug(msg)

    def crit(self, msg):
        return self.log.critical(msg)
    
    def set_level(self, level):
        for h in self.log.handlers:
            h.setLevel(level.upper())
        self.log.setLevel(level.upper())
        return True
        
