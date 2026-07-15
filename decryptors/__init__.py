# decryptors/__init__.py - Updated mapping

from .http_custom import run as run_hc
from .ehi import run as run_ehi
from .npvt import run as run_npvt
from .ssc import run as run_ssc
from .dark_tunnel import run as run_dark
from .dark_cloud_decryptor import run as run_dark_cloud

DECRYPTORS = {
    '.hc': run_hc,
    '.ehi': run_ehi,
    '.npvt': run_npvt,
    '.ssc': run_ssc,
    '.dark': run_dark,
    '.darktunnel': run_dark,  # Explicit dark tunnel
    '.darkcloud': run_dark_cloud,
}

# --- dark_cloud_decryptor.py (keep as is, already has run() function) ---