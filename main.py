import sys, os

os.chdir(os.path.dirname(os.path.abspath(__file__)))
sys.path.append('.')

import Measure.Measure as MS

if __name__ == '__main__':
    MS.StartMeasure()