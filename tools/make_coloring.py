import argparse
import sys

def main():
    args = arg_processing()
    
    with open(args.file_path, 'a') as file:
        file.write('@' + args.label + '@zdp.type')
        if len(args.packet_type) == 1:
            file.write(' == ' + str(args.packet_type[0]) + '@')
        else:
            file.write(' in {')
            length = len(args.packet_type)
            for i, pt in enumerate(args.packet_type):
                file.write(str(pt))
                if i + 1 != length:
                    file.write(', ') 
            file.write('}@')
        r = str(args.color[0] * 257) # Convert from standard 8-bit color values to 16-bit used by Wireshark
        g = str(args.color[1] * 257)
        b = str(args.color[2] * 257)
        file.write('[' + r + ',' + g + ',' + b + ']')
        tc = args.text_color.lower() 
        if tc == 'white' or tc == 'w':
            file.write('[65535,65535,65535]')
        else:
            file.write('[0,0,0]')
        file.write('\n')
        
def arg_processing():
    parser = argparse.ArgumentParser(description='Create custom Lua coloring for ZDP')
    parser.add_argument('-c', '--color', type=int, nargs=3, required=True, metavar=('RED', 'GREEN', 'BLUE'))
    parser.add_argument('-f', '--file-path', type=str, default='colors.txt')
    parser.add_argument('-p', '--packet-type', type=int, nargs='+', required=True)
    parser.add_argument('-l', '--label', type=str, required=True)
    parser.add_argument('-t', '--text-color', type=str, default='black')

    args = parser.parse_args()

    tc = args.text_color.lower()

    print(tc)

    if tc != 'black' and tc != 'white' and tc != 'b' and tc != 'w':
        sys.stderr.write('Text color must be black or white')
        exit(1)

    return args


if __name__ == '__main__':
    main()