from .http_custom import run as run_hc
from .ehi import run as run_ehi
from .npvt import run as run_npvt
from .ssc import run as run_ssc
from .dark_tunnel import run as run_dark

# Map file extensions to their run functions
DECRYPTORS = {
    '.hc': run_hc,
    '.ehi': run_ehi,
    '.npvt': run_npvt,
    '.ssc': run_ssc,
    '.dark': run_dark,
}

# Also map by content magic (optional)
# You can extend with file header detection