#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <math.h>
#include <stdbool.h>

typedef struct Arguments
{
    bool encrypt;
    bool decrypt;
    bool inputFromFile;
    bool outputToFile;
    char *inputMessage;
    char *outputMessage;
    char *inputFile;
    char *outputFile;
    char forwardkey[27];
    char reverseKey[27];
} args;

void printError(int e)
{
    switch (e)
    {
    case 1:
        printf("Error: Missing required arguments. Use '-h' to view the usage guide.");
        break;

    case 2:
        printf("Error: Invalid command-line argument. Use '-h' to view the usage guide.");
        break;

    case 3:
        printf("Error: Encryption (-e) and decryption (-d) cannot be specified together.");
        break;

    case 4:
        printf("Error: Specify either a message (-m) or an input file (-f), not both.");
        break;

    case 5:
        printf("Error: No substitution key specified. Use '-k <key>'.");
        break;

    case 6:
        printf("Error: No operation specified. Choose either '-e' or '-d'.");
        break;

    case 7:
        printf("Error: No input source specified. Use '-m <message>' or '-f <file>'.");
        break;

    case 8:
        printf("Error: Unrecognized command-line argument.");
        break;

    case 9:
        printf("Error: No message specified after '-m'.");
        break;

    case 10:
        printf("Error: No input file specified after '-f'.");
        break;

    case 11:
        printf("Error: No output file specified after '-o'.");
        break;

    case 12:
        printf("Error: Duplicate command-line argument detected.");
        break;

    case 13:
        printf("Error: Unable to create or access the output file.");
        break;

    case 14:
        printf("Error: Input file not found.");
        break;

    case 15:
        printf("Error: Invalid input file path.");
        break;

    case 16:
        printf("Error: Invalid output file path.");
        break;

    case 17:
        printf("Error: The help option (-h) cannot be combined with other arguments.");
        break;

    case 18:
        printf("Error: The substitution key must contain exactly 26 alphabetic characters.");
        break;

    case 19:
        printf("Error: The substitution key contains duplicate characters. Each letter must appear exactly once.");
        break;

    case 20:
        printf("Error: The substitution key may contain alphabetic characters only.");
        break;

    default:
        break;
    }
}

void printHelp()
{
    printf("CipherCLI\n\n");

    printf("Usage:\n");
    printf("  ./ciphercli -e -k <key> -m <message>\n");
    printf("  ./ciphercli -d -k <key> -m <message>\n");
    printf("  ./ciphercli -e -k <key> -f <input> [-o <output>]\n");
    printf("  ./ciphercli -d -k <key> -f <input> [-o <output>]\n\n");

    printf("Options:\n");
    printf("  %-6s Encrypt input\n", "-e");
    printf("  %-6s Decrypt input\n", "-d");
    printf("  %-6s Specify substitution key\n", "-k");
    printf("  %-6s Read input from command line\n", "-m");
    printf("  %-6s Read input from a file\n", "-f");
    printf("  %-6s Write output to a file\n", "-o");
    printf("  %-6s Display this help message\n", "-h");
}

void tagType(int argc, char **argv, int *e, int *d, int *m, int *f, int *o, int *k, int *h, int *narg, int *ep, int *dp, int *mp, int *fp, int *op, int *kp)
{
    for (int i = 1; i < argc; i++)
    {
        if (strlen(argv[i]) == 2)
        {
            if ((strncmp("-e", argv[i], 2)) == 0 || (strncmp("-E", argv[i], 2)) == 0)
            {
                *ep = i;
                *e = *e + 1;
                *narg = *narg + 1;
            }
            else if ((strncmp("-d", argv[i], 2)) == 0 || (strncmp("-D", argv[i], 2)) == 0)
            {
                *dp = i;
                *d = *d + 1;
                *narg = *narg + 1;
            }
            else if ((strncmp("-m", argv[i], 2)) == 0 || (strncmp("-M", argv[i], 2)) == 0)
            {
                *mp = i;
                *m = *m + 1;
                *narg = *narg + 2;
            }
            else if ((strncmp("-f", argv[i], 2)) == 0 || (strncmp("-F", argv[i], 2)) == 0)
            {
                *fp = i;
                *f = *f + 1;
                *narg = *narg + 2;
            }
            else if ((strncmp("-o", argv[i], 2)) == 0 || (strncmp("-O", argv[i], 2)) == 0)
            {
                *op = i;
                *o = *o + 1;
                *narg = *narg + 2;
            }
            else if ((strncmp("-k", argv[i], 2)) == 0 || (strncmp("-K", argv[i], 2)) == 0)
            {
                *kp = i;
                *k = *k + 1;
                *narg = *narg + 2;
            }
            else if ((strncmp("-h", argv[i], 2)) == 0 || (strncmp("-H", argv[i], 2)) == 0 || (strncmp("-?", argv[i], 2)) == 0)
            {
                *h = *h + 1;
            }
        }
        else if (strlen(argv[i]) == 1 && (strncmp("?", argv[i], 1)) == 0)
        {
            *h = *h + 1;
        }
    }
}

int tagTypeSingle(char *argv)
{
    if (strlen(argv) == 2)
    {
        if ((strncmp("-e", argv, 2)) == 0 || (strncmp("-E", argv, 2)) == 0)
        {
            return 1;
        }
        else if ((strncmp("-d", argv, 2)) == 0 || (strncmp("-D", argv, 2)) == 0)
        {
            return 2;
        }
        else if ((strncmp("-m", argv, 2)) == 0 || (strncmp("-M", argv, 2)) == 0)
        {
            return 9;
        }
        else if ((strncmp("-f", argv, 2)) == 0 || (strncmp("-F", argv, 2)) == 0)
        {
            return 10;
        }
        else if ((strncmp("-o", argv, 2)) == 0 || (strncmp("-O", argv, 2)) == 0)
        {
            return 11;
        }
        else if ((strncmp("-k", argv, 2)) == 0 || (strncmp("-K", argv, 2)) == 0)
        {
            return 5;
        }
        else if ((strncmp("-h", argv, 2)) == 0 || (strncmp("-H", argv, 2)) == 0 || (strncmp("-?", argv, 2)) == 0)
        {
            return 7;
        }
    }
    else if ((strlen(argv) == 1) && (strncmp("?", argv, 1)) == 0)
    {
        return 7;
    }

    return 0;
}

int keyValidate(char *kc, struct Arguments *args)
{
    size_t s = strlen(kc);
    for (size_t i = 0; i < s; i++)
    {
        kc[i] = (char)tolower(kc[i]);
    }

    if (s == 26)
    {
        bool seen[26] = {false};

        for (int i = 0; i < 26; i++)
        {
            if (isalpha(kc[i]) != 0)
            {
                int index = tolower(kc[i]) - 'a';

                if (seen[index])
                {
                    printError(19);
                    return 0;
                }

                seen[index] = true;
            }
            else
            {
                printError(20);
                return 0;
            }
        }
    }
    else
    {
        printError(18);
        return 0;
    }

    strcpy(args->forwardkey, kc);

    for (int i = 0; i < 26; i++)
    {
        int pos = kc[i] - 'a';
        (args->reverseKey)[pos] = (char)(i + 'a');
    }
    (args->reverseKey)[26] = '\0';
    return 1;
}

int errorType(int argc, char **argv, int e, int d, int m, int f, int o, int k, int h, int narg, int ep, int dp, int mp, int fp, int op, int kp, char *mc, char *fc, char *oc, char *kc, struct Arguments *args)
{

    if (argc == 1)
    {
        printError(1);
        return 0;
    }
    if (argc > 2 && h > 0)
    {
        printError(17);
        return 0;
    }
    if (argc == 2 && h == 1)
    {
        printHelp();
        return 0;
    }
    if (e > 0 && d > 0)
    {
        printError(3);
        return 0;
    }
    if (m > 0 && f > 0)
    {
        printError(4);
        return 0;
    }
    if (e == 0 && d == 0)
    {
        printError(6);
        return 0;
    }
    if ((m == 0 && f == 0))
    {
        printError(7);
        return 0;
    }

    if (argc < narg)
    {
        int ps[] = {ep, dp, mp, fp, op, kp};
        for (int i = 0; i < 6; i++)
        {
            for (int j = 0; j < 6 - i - 1; j++)
            {
                if (ps[j] > ps[j + 1])
                {
                    int temp = ps[j];
                    ps[j] = ps[j + 1];
                    ps[j + 1] = temp;
                }
                else
                {
                    continue;
                }
            }
        }
        for (int i = 0; i < 5; i++)
        {
            if (ps[i] == 0 || ps[i] == ep || ps[i] == dp)
            {
                continue;
            }
            else if (ps[i] - ps[i + 1] > -2)
            {
                printError(tagTypeSingle(argv[ps[i]]));
                return 0;
            }
        }
    }
    if (argc > narg)
    {
        printError(8);
        return 0;
    }

    for (int j = 1; j < argc; j++)
    {
        size_t s = strlen(argv[j]);
        if (j == ep || j == dp)
        {
            continue;
        }
        else if (j == mp || j == fp || j == op || j == kp)
        {
            if (j == argc - 1)
            {
                printError(tagTypeSingle(argv[j]));
                return 0;
            }
        }

        else if (j == mp + 1)
        {
            if ((tagTypeSingle(argv[mp + 1]) != 0) || (mp + 1 == argc))
            {
                printError(9);
                return 0;
            }
            else
            {
                char *temp = realloc(mc, ((s + 1) * sizeof(char)));
                if (temp == NULL)
                {
                    free(mc);
                    printf("Dynamic memory allocation failed. Please run program again.\n");
                    return 0;
                }

                mc = temp;
                strcpy(mc, argv[j]);
                args->inputMessage = mc;
            }
        }
        else if (j == fp + 1)
        {
            if ((strncmp(&(argv[fp + 1][s]) - 4, ".txt", 4) != 0) || s < 5)
            {
                printError(15);
                return 0;
            }
            else
            {
                char *temp = realloc(fc, ((s + 1) * sizeof(char)));
                if (temp == NULL)
                {
                    free(fc);
                    printf("Dynamic memory allocation failed. Please run program again.\n");
                    return 0;
                }

                fc = temp;
                strcpy(fc, argv[j]);
                args->inputFromFile = true;
                args->inputFile = fc;
            }
        }
        else if (j == op + 1)
        {
            if ((strncmp(&(argv[op + 1][s]) - 4, ".txt", 4) != 0) || s < 5)
            {
                printError(16);
                return 0;
            }
            else
            {
                char *temp = realloc(oc, ((s + 1) * sizeof(char)));
                if (temp == NULL)
                {
                    free(oc);
                    printf("Dynamic memory allocation failed. Please run program again.\n");
                    return 0;
                }

                oc = temp;
                strcpy(oc, argv[j]);
                args->outputToFile = true;
                args->outputFile = oc;
            }
        }
        else if (j == kp + 1)
        {

            strcpy(kc, argv[j]);
            if (keyValidate(kc, args) == 0)
            {
                return 0;
            }
            // else
            // {
            //     // char *temp = realloc(kc, ((s + 1) * sizeof(char)));
            //     // if (temp == NULL)
            //     // {
            //     //     free(kc);
            //     //     printf("Dynamic memory allocation failed. Please run program again.\n");
            //     //     return 0;
            //     // }

            //     // kc = temp;
            //     strcpy(args->key, argv[j]);
            // }
        }
        else
        {
            printError(8);
            return 0;
        }
    }

    if (k == 0)
    {
        printError(5);
        return 0;
    }
    if (m == 1 && ((tagTypeSingle(argv[mp + 1]) != 0) || (mp + 1 == argc)))
    {
        printError(9);
        return 0;
    }
    size_t s1 = strlen(argv[fp + 1]);
    if (f == 1 && ((tagTypeSingle(argv[fp + 1]) != 0) || (fp + 1 == argc) || (strncmp(&argv[fp + 1][s1] - 4, ".txt", 4) != 0) || s1 < 5))
    {
        printError(10);
        return 0;
    }
    size_t s2 = strlen(argv[op + 1]);
    if (o == 1 && ((tagTypeSingle(argv[op + 1]) != 0) || (op + 1 == argc) || (strncmp(&argv[op + 1][s2] - 4, ".txt", 4) != 0) || s2 < 5))
    {
        printError(11);
        return 0;
    }
    if (e > 1 || d > 1 || m > 1 || f > 1 || o > 1 || k > 1)
    {
        printError(12);
        return 0;
    }

    return 1;
}

int parseArgument(int argc, char **argv, struct Arguments *args)
{
    char *mc = calloc(100, sizeof(char));
    char *kc = calloc(100, sizeof(char));
    char *oc = calloc(100, sizeof(char));
    char *fc = calloc(100, sizeof(char));

    int e = 0, d = 0, m = 0, f = 0, o = 0, k = 0, h = 0, narg = 1, ep = 0, dp = 0, mp = 0, fp = 0, op = 0, kp = 0;

    tagType(argc, argv, &e, &d, &m, &f, &o, &k, &h, &narg, &ep, &dp, &mp, &fp, &op, &kp);
    if (errorType(argc, argv, e, d, m, f, o, k, h, narg, ep, dp, mp, fp, op, kp, mc, fc, oc, kc, args) == 0)
    {
        return 0;
    }

    if (e == 1)
    {
        args->encrypt = true;
    }
    else if (d == 1)
    {
        args->decrypt = true;
    }
    return 1;

    // if (e == 1 && m == 1 && o == 1)
    // {
    //     fc = NULL;
    //     return 1;
    // }
    // else if (e == 1 && m == 1 && o == 0)
    // {
    //     fc = NULL;
    //     oc = NULL;
    //     return 1;
    // }
    // else if (e == 1 && f == 1 && o == 1)
    // {
    //     mc = NULL;
    //     return 1;
    // }
    // else if (e == 1 && f == 1 && o == 0)
    // {
    //     mc = NULL;
    //     oc = NULL;
    //     return 2;
    // }
    // else if (d == 1 && m == 1 && o == 1)
    // {
    //     fc = NULL;
    //     return 2;
    // }
    // else if (d == 1 && m == 1 && o == 0)
    // {
    //     fc = NULL;
    //     oc = NULL;
    //     return 2;
    // }
    // else if (d == 1 && f == 1 && o == 1)
    // {
    //     mc = NULL;
    //     return 2;
    // }
    // else if (d == 1 && f == 1 && o == 0)
    // {
    //     mc = NULL;
    //     oc = NULL;
    //     return 2;
    // }

    // if (e == 1 && m == 1 && o == 1)
    // {
    //     char **fa = malloc(4 * sizeof(char *));
    //     fa[0] = "1";
    //     fa[1] = mc;
    //     fa[2] = oc;
    //     fa[3] = kc;
    //     return fa;
    // }
    // else if (e == 1 && m == 1 && o == 0)
    // {
    //     char **fa = malloc(3 * sizeof(char *));
    //     fa[0] = "2";
    //     fa[1] = mc;
    //     fa[2] = kc;
    //     return fa;
    // }
    // else if (e == 1 && f == 1 && o == 1)
    // {
    //     char **fa = malloc(4 * sizeof(char *));
    //     fa[0] = "3";
    //     fa[1] = fc;
    //     fa[2] = oc;
    //     fa[3] = kc;
    //     return fa;
    // }
    // else if (e == 1 && f == 1 && o == 0)
    // {
    //     char **fa = malloc(3 * sizeof(char *));
    //     fa[0] = "4";
    //     fa[1] = fc;
    //     fa[2] = kc;
    //     return fa;
    // }
    // else if (d == 1 && m == 1 && o == 1)
    // {
    //     char **fa = malloc(4 * sizeof(char *));
    //     fa[0] = "5";
    //     fa[1] = mc;
    //     fa[2] = oc;
    //     fa[3] = kc;
    //     return fa;
    // }
    // else if (d == 1 && m == 1 && o == 0)
    // {
    //     char **fa = malloc(3 * sizeof(char *));
    //     fa[0] = "6";
    //     fa[1] = mc;
    //     fa[2] = kc;
    //     return fa;
    // }
    // else if (d == 1 && f == 1 && o == 1)
    // {
    //     char **fa = malloc(4 * sizeof(char *));
    //     fa[0] = "7";
    //     fa[1] = fc;
    //     fa[2] = oc;
    //     fa[3] = kc;
    //     return fa;
    // }
    // else if (d == 1 && f == 1 && o == 0)
    // {
    //     char **fa = malloc(3 * sizeof(char *));
    //     fa[0] = "8";
    //     fa[1] = fc;
    //     fa[2] = kc;
    //     return fa;
    // }
}

int writeFile(struct Arguments *args)
{
    FILE *fp;
    fp = fopen(args->outputFile, "w");
    if (fp == NULL)
    {
        return 0;
    }
    int i = 0;
    while ((args->outputMessage)[i] != '\0')
    {
        fputc((args->outputMessage)[i], fp);
        i++;
    }
    fclose(fp);
    return 1;
}

int readFile(struct Arguments *args)
{
    FILE *fp;
    fp = fopen(args->inputFile, "r");
    if (fp == NULL)
    {
        return 0;
    }
    int c;
    unsigned int size = 128, filled = 0;
    char *m = calloc(128, sizeof(char));
    while ((c = fgetc(fp)) != EOF)
    {
        m[filled] = (char)c;
        filled++;
        if (filled >= size - 1)
        {
            char *temp = realloc(m, (size *= 2) * sizeof(char));
            if (temp == NULL)
            {
                free(m);
                printf("Dynamic memory allocation failed. Please run program again.\n");
                return 0;
            }

            m = temp;
        }
    }
    m[filled] = '\0';
    fclose(fp);
    args->inputMessage = m;
    return 1;
}

char *transformText(struct Arguments *args)
{
    size_t n = strlen(args->inputMessage);
    char *fm = calloc(n + 1, sizeof(char));
    if (args->encrypt)
    {
        for (size_t i = 0; i < n; i++)
        {
            if (isalpha((args->inputMessage)[i]))
            {
                int pos = tolower((args->inputMessage)[i]) - 97;
                fm[i] = (args->forwardkey)[pos];
                if (isupper((args->inputMessage)[i]))
                {
                    fm[i] = (char)toupper(fm[i]);
                }
            }
            else
            {
                fm[i] = (args->inputMessage)[i];
            }
        }
    }
    else if (args->decrypt)
    {
        for (size_t i = 0; i < n; i++)
        {
            // if (isalpha((args->inputMessage)[i]))
            // {
            //     char *p = strchr(args->forwardkey, tolower((args->inputMessage)[i]));
            //     if (p != NULL)
            //     {
            //         int pos = p - args->forwardkey;
            //         fm[i] = (char)('a' + pos);
            //         if (isupper((args->inputMessage)[i]))
            //         {
            //             fm[i] = toupper(fm[i]);
            //         }
            //     }
            // }
            if (isalpha((args->inputMessage)[i]))
            {
                int pos = tolower((args->inputMessage)[i]) - 97;
                fm[i] = (args->reverseKey)[pos];
                if (isupper((args->inputMessage)[i]))
                {
                    fm[i] = (char)toupper(fm[i]);
                }
            }
            else
            {
                fm[i] = (args->inputMessage)[i];
            }
        }
    }
    fm[n] = '\0';
    args->outputMessage = fm;
    return fm;
}

int main(int argc, char **argv)
{
    printf("CipherCLI: ");
    args args = {0};
    // char **fa = parseArgument(argc, argv);
    int fa = parseArgument(argc, argv, &args);

    if (fa == 0)
    {
        return 0;
    }
    if (args.inputFromFile)
    {
        if (readFile(&args) == 0)
        {
            printError(14);
            return 0;
        }
    }
    transformText(&args);
    // if (args.encrypt)
    // {
    //     transformText("1", m, kc);
    //     free(mc);
    //     free(kc);
    // }
    // else if (fa == 2)
    // {
    //     transformText("2", m, kc);
    //     free(mc);
    //     free(kc);
    // }
    if (args.outputToFile)
    {
        if (writeFile(&args) == 0)
        {
            printError(13);
            return 0;
        }
        printf("Message has been written to the specified output file.");
    }
    else if (args.outputToFile == false)
    {
        printf("Encrypted Text: %s", args.outputMessage);
    }

    // else if (strncmp(fa[0], "1", 1) == 0)
    // {
    //     char *fm = transformText('1', fa[1], fa[3]);
    //     fileHandler(fa[2], "w", fm);
    //     printf("Message has been written to the specified output file.");
    // }
    // else if (strncmp(fa[0], "2", 1) == 0)
    // {
    //     char *fm = transformText('1', fa[1], fa[2]);
    //     printf("Encrypted Text: %s", fm);
    // }
    // else if (strncmp(fa[0], "3", 1) == 0)
    // {
    //     char *m = fileHandler(fa[1], "r", NULL);
    //     if (m == NULL)
    //     {
    //         printError(14);
    //         return 0;
    //     }
    //     char *fm = transformText('1', m, fa[3]);
    //     fileHandler(fa[2], "w", fm);
    //     printf("Message has been written to the specified output file.");
    // }
    // else if (strncmp(fa[0], "4", 1) == 0)
    // {
    //     char *m = fileHandler(fa[1], "w", NULL);
    //     if (m == NULL)
    //     {
    //         printError(14);
    //         return 0;
    //     }
    //     char *fm = transformText('1', m, fa[2]);
    //     printf("Encrypted Text: %s", fm);
    // }
    // else if (strncmp(fa[0], "5", 1) == 0)
    // {
    //     char *fm = transformText('2', fa[1], fa[3]);
    //     fileHandler(fa[2], "w", fm);
    //     printf("Message has been written to the specified output file.");
    // }
    // else if (strncmp(fa[0], "6", 1) == 0)
    // {
    //     char *fm = transformText('2', fa[1], fa[2]);
    //     printf("Encrypted Text: %s", fm);
    // }
    // else if (strncmp(fa[0], "7", 1) == 0)
    // {
    //     char *m = fileHandler(fa[1], "r", NULL);
    //     if (m == NULL)
    //     {
    //         printError(14);
    //         return 0;
    //     }
    //     char *fm = transformText('2', m, fa[3]);
    //     fileHandler(fa[2], "w", fm);
    //     printf("Message has been written to the specified output file.");
    // }
    // else if (strncmp(fa[0], "8", 1) == 0)
    // {
    //     char *m = fileHandler(fa[1], "r", NULL);
    //     if (m == NULL)
    //     {
    //         printError(14);
    //         return 0;
    //     }
    //     char *fm = transformText('2', m, fa[2]);
    //     printf("Encrypted Text: %s", fm);
    // }

    return 0;
}