__author__ = '@awhitehatter'
__version__ = '2.1'


from core.ui import Colors, banner
from core.utils import menu, logger, dangerzone_warning, dangerzone_confirm


def main():
    """Main function for Mailoney"""

    # Parse command line options
    parser = menu()
    args = parser.parse_args()
    bind_ip = args.i
    bind_port = int(args.p)
    srvname = args.s
    enable_dangerzone = args.dangerzone

    # Create the banner
    version = __version__
    banner(version)

    # set up logging
    logger()

    # Check for Dangerzone Mode
    if enable_dangerzone == True:
        dangerzone_warning()
        dangerzone_confirm()



if __name__ == '__main__':
    main()
