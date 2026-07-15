# decryptors/__init__.py - Updated with EHI cloud

from .http_custom import run as run_hc
from .ehi import run as run_ehi
from .npvt import run as run_npvt
from .ssc import run as run_ssc
from .dark_tunnel import run as run_dark
from .dark_cloud_decryptor import run as run_dark_cloud
from .ehi_cloud import run as run_ehi_cloud

DECRYPTORS = {
    '.hc': run_hc,
    '.ehi': run_ehi,
    '.npvt': run_npvt,
    '.ssc': run_ssc,
    '.dark': run_dark,
    '.darktunnel': run_dark,
    '.darkcloud': run_dark_cloud,
    '.ehi_cloud': run_ehi_cloud,  # EHI cloud decryptor
}