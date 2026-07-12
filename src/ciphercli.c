/*
 * CipherCLI
 * ---------
 * A simple command-line substitution-cipher tool.
 *
 * Usage:
 *   ciphercli -e -k <key> -m <message>
 *   ciphercli -d -k <key> -m <message>
 *   ciphercli -e -k <key> -f <input.txt> [-o <output.txt>]
 *   ciphercli -d -k <key> -f <input.txt> [-o <output.txt>]
 *
 * <key> must be a 26-letter permutation of the alphabet, e.g.
 * "qwertyuiopasdfghjklzxcvbnm".
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <math.h>
#include <stdbool.h>
#include <time.h>

typedef struct Arguments
{
    bool encrypt;
    bool decrypt;
    bool inputFromFile;
    bool outputToFile;
    bool keyIsGenerated;
    char *inputMessage;  /* heap-owned; freed by freeArgs() */
    char *outputMessage; /* heap-owned; freed by freeArgs() */
    char *inputFile;     /* heap-owned; freed by freeArgs() */
    char *outputFile;    /* heap-owned; freed by freeArgs() */
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
        printf("Error: No substitution key specified. Use '-k <key>' or '-g' to generate one.");
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

    case 21:
        printf("Error: Either specify a key (-k) or generate one (-g), not both.");
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
    printf("  %-6s Generate substitution key\n", "-g");
    printf("  %-6s Read input from command line\n", "-m");
    printf("  %-6s Read input from a file\n", "-f");
    printf("  %-6s Write output to a file\n", "-o");
    printf("  %-6s Display this help message\n", "-h");
}

char *keyGenerate(struct Arguments *args)
{
    int *lowerAscii = calloc(26, sizeof(int));
    char *key = calloc(26, sizeof(char));
    for (int i = 0; i < 26; i++)
    {
        lowerAscii[i] = 97 + i;
    }
    for (int j = 0; j < 26; j++)
    {
        srand(time(NULL));
        int r = rand() % (26 - j);
        key[j] = (char)lowerAscii[r];
        lowerAscii[r] = lowerAscii[25 - j];
        if (25 - j == 0)
        {
            free(lowerAscii);
        }
        else
        {
            lowerAscii = realloc(lowerAscii, ((25 - j) * sizeof(int)));
        }
    }
    key[26] = '\0';
    strcpy(args->forwardkey, key);
    for (int i = 0; i < 26; i++)
    {
        int pos = key[i] - 'a';
        (args->reverseKey)[pos] = (char)(i + 'a');
    }
    (args->reverseKey)[26] = '\0';
    free(key);
}

/*
 * Classifies every argv entry, tallying how many times each flag appears
 * and recording the argv index of its most recent occurrence. Duplicate
 * detection relies on the counts (e, d, m, f, o, k), not the positions.
 */
void tagType(int argc, char **argv, int *e, int *d, int *m, int *f, int *o, int *k, int *g, int *h, int *narg, char ***ep, char ***dp, char ***mp, char ***fp, char ***op, char ***kp, char ***gp)
{
    for (int i = 1; i < argc; i++)
    {
        if (strlen(argv[i]) == 2)
        {
            if ((strncmp("-e", argv[i], 2)) == 0 || (strncmp("-E", argv[i], 2)) == 0)
            {
                *ep = (argv + i);
                *e = *e + 1;
                *narg = *narg + 1;
            }
            else if ((strncmp("-d", argv[i], 2)) == 0 || (strncmp("-D", argv[i], 2)) == 0)
            {
                *dp = (argv + i);
                *d = *d + 1;
                *narg = *narg + 1;
            }
            else if ((strncmp("-m", argv[i], 2)) == 0 || (strncmp("-M", argv[i], 2)) == 0)
            {
                *mp = (argv + i);
                *m = *m + 1;
                *narg = *narg + 2;
            }
            else if ((strncmp("-f", argv[i], 2)) == 0 || (strncmp("-F", argv[i], 2)) == 0)
            {
                *fp = (argv + i);
                *f = *f + 1;
                *narg = *narg + 2;
            }
            else if ((strncmp("-o", argv[i], 2)) == 0 || (strncmp("-O", argv[i], 2)) == 0)
            {
                *op = (argv + i);
                *o = *o + 1;
                *narg = *narg + 2;
            }
            else if ((strncmp("-k", argv[i], 2)) == 0 || (strncmp("-K", argv[i], 2)) == 0)
            {
                *kp = (argv + i);
                *k = *k + 1;
                *narg = *narg + 2;
            }
            else if ((strncmp("-g", argv[i], 2)) == 0 || (strncmp("-G", argv[i], 2)) == 0)
            {
                *gp = (argv + i);
                *g = *g + 1;
                *narg = *narg + 1;
            }
            else if ((strncmp("-h", argv[i], 2)) == 0 || (strncmp("-H", argv[i], 2)) == 0 || (strncmp("-?", argv[i], 2)) == 0)
            {
                *h = *h + 1;
                *narg = *narg + 1;
            }
        }
        else if (strlen(argv[i]) == 1 && (strncmp("?", argv[i], 1)) == 0)
        {
            *h = *h + 1;
            *narg = *narg + 1;
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
        else if ((strncmp("-g", argv, 2)) == 0 || (strncmp("-G", argv, 2)) == 0)
        {
            return 3;
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

/*
 * Checks whether `filename` ends in ".txt", case-insensitively (so both
 * "data.txt" and "DATA.TXT" are accepted).
 *
 * The length check happens first and short-circuits before any pointer
 * arithmetic is performed, so this never walks off the front of a short
 * or empty string.
 */
static bool hasValidTxtExtension(const char *filename)
{
    if (filename == NULL)
    {
        return false;
    }

    size_t len = strlen(filename);
    if (len < 5) /* shortest valid name is "a.txt" (1 char + ".txt") */
    {
        return false;
    }

    const char *ext = filename + (len - 4);
    return ext[0] == '.' &&
           tolower((unsigned char)ext[1]) == 't' &&
           tolower((unsigned char)ext[2]) == 'x' &&
           tolower((unsigned char)ext[3]) == 't';
}

/*
 * Validates and normalizes the substitution key, then derives the
 * forward and reverse lookup tables into `args`.
 *
 * Note: ctype.h functions (isalpha/tolower/etc.) are only defined for
 * values representable as `unsigned char` or EOF. On platforms where
 * `char` is signed (the common case, e.g. x86 Linux), any byte with its
 * high bit set (>= 0x80 -- accented letters, UTF-8 continuation bytes,
 * etc.) becomes a *negative* int when passed as a plain `char`, which is
 * undefined behavior. We cast to `unsigned char` everywhere before
 * calling into ctype.h to avoid this.
 */
int keyValidate(char *kc, struct Arguments *args)
{
    size_t s = strlen(kc);
    for (size_t i = 0; i < s; i++)
    {
        kc[i] = (char)tolower((unsigned char)kc[i]);
    }

    if (s == 26)
    {
        bool seen[26] = {false};

        for (int i = 0; i < 26; i++)
        {
            if (isalpha((unsigned char)kc[i]) != 0)
            {
                int index = tolower((unsigned char)kc[i]) - 'a';

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

/*
 * Validates the full argument set and, on success, copies the relevant
 * values into `args`.
 *
 * Ownership note: mc/fc/oc/kc are passed as pointer-to-pointer so that
 * when a buffer is grown with realloc() here, the caller's copy of the
 * pointer is updated too. Realloc failures are simply
 * reported and left for the single free() pass in parseArgument to
 * clean up, so there is exactly one place in the whole program that
 * ever frees these buffers.
 */
int errorType(int argc, char **argv, int e, int d, int m, int f, int o, int k, int g, int h, int narg, char **ep, char **dp, char **mp, char **fp, char **op, char **kp, char **gp, char **mc, char **fc, char **oc, char **kc, struct Arguments *args)
{

    if (argc == 1)
    {
        printError(1);
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
    if (k > 0 && g > 0)
    {
        printError(21);
        return 0;
    }
    if (e == 0 && d == 0)
    {
        printError(6);
        return 0;
    }
    if (m == 0 && f == 0)
    {
        printError(7);
        return 0;
    }
    if (k == 0 && g == 0)
    {
        printError(5);
        return 0;
    }
    if (e > 1 || d > 1 || m > 1 || f > 1 || o > 1 || k > 1 || h > 1)
    {
        printError(12);
        return 0;
    }
    if (argc > 2 && h > 0)
    {
        printError(17);
        return 0;
    }

    if (argc < narg)
    {
        char **ps[] = {ep, dp, mp, fp, op, kp, gp};
        for (int i = 0; i < 7; i++)
        {
            for (int j = 0; j < 7 - i - 1; j++)
            {
                if (ps[j] > ps[j + 1])
                {
                    char **temp = ps[j];
                    ps[j] = ps[j + 1];
                    ps[j + 1] = temp;
                }
                else
                {
                    continue;
                }
            }
        }
        for (int i = 0; i < 6; i++)
        {
            if (ps[i] == 0 || ps[i] == ep || ps[i] == dp || ps[i] == gp)
            {
                continue;
            }
            else if (ps[i] - ps[i + 1] > -4)
            {
                printError(tagTypeSingle(*(ps[i])));
                return 0;
            }
        }
    }
    if (argc > narg)
    {
        printError(8);
        return 0;
    }

    for (char **j = argv + 1; j < argv + argc; j++)
    {
        size_t s = strlen(*j);
        if (j == ep || j == dp || j == gp)
        {
            continue;
        }
        else if (j == mp || j == fp || j == op || j == kp)
        {
            if (j == argv + (argc - 1))
            {
                printError(tagTypeSingle(*j));
                return 0;
            }
        }

        else if (j == mp + 1)
        {

            if ((tagTypeSingle(*(mp + 1)) != 0) || (mp == argv + (argc - 1)))
            {
                printError(9);
                return 0;
            }
            else
            {
                char *temp = realloc(*mc, ((s + 1) * sizeof(char)));
                if (temp == NULL)
                {
                    printf("Dynamic memory allocation failed. Please run program again.\n");
                    return 0;
                }

                *mc = temp;
                strcpy(*mc, *j);
                args->inputMessage = *mc;
            }
        }
        else if (j == fp + 1)
        {
            if (!hasValidTxtExtension(*(fp + 1)))
            {
                printError(15);
                return 0;
            }
            else
            {
                char *temp = realloc(*fc, ((s + 1) * sizeof(char)));
                if (temp == NULL)
                {
                    printf("Dynamic memory allocation failed. Please run program again.\n");
                    return 0;
                }

                *fc = temp;
                strcpy(*fc, *j);
                args->inputFromFile = true;
                args->inputFile = *fc;
            }
        }
        else if (j == op + 1)
        {
            if (!hasValidTxtExtension(*(op + 1)))
            {
                printError(16);
                return 0;
            }
            else
            {
                char *temp = realloc(*oc, ((s + 1) * sizeof(char)));
                if (temp == NULL)
                {
                    printf("Dynamic memory allocation failed. Please run program again.\n");
                    return 0;
                }

                *oc = temp;
                strcpy(*oc, *j);
                args->outputToFile = true;
                args->outputFile = *oc;
            }
        }
        else if (j == kp + 1)
        {
            char *temp = realloc(*kc, ((s + 1) * sizeof(char)));
            if (temp == NULL)
            {
                printf("Dynamic memory allocation failed. Please run program again.\n");
                return 0;
            }

            *kc = temp;
            strcpy(*kc, *j);
            if (keyValidate(*kc, args) == 0)
            {
                return 0;
            }
        }
        else
        {
            printError(8);
            return 0;
        }
    }

    if (m == 1 && ((tagTypeSingle(*(mp + 1)) != 0) || (mp == argv + (argc - 1))))
    {
        printError(9);
        return 0;
    }
    if (f == 1 && ((tagTypeSingle(*(fp + 1)) != 0) || (fp == argv + (argc - 1)) || !hasValidTxtExtension(*(fp + 1))))
    {
        printError(10);
        return 0;
    }
    if (o == 1 && ((tagTypeSingle(*(op + 1)) != 0) || (op == argv + (argc - 1)) || !hasValidTxtExtension(*(op + 1))))
    {
        printError(11);
        return 0;
    }

    return 1;
}

/*
 * Parses argv into `args`.
 *
 * Buffer lifetime: mc/kc/oc/fc are scratch buffers owned exclusively by
 * this function. errorType() may grow them via realloc() (through the
 * pointer-to-pointer parameters) and, on success, copies the ones that
 * are actually used into `args` for later use (inputMessage, inputFile,
 * outputFile). `kc` is never stored in `args` -- keyValidate() only
 * copies its contents into args->forwardkey/reverseKey -- so it is
 * always freed here regardless of outcome.
 *
 * On failure, all four buffers still point at valid, owned allocations
 * (either their original calloc() or a successful realloc()), so a
 * single free() per buffer is always correct and never a double-free.
 */
int parseArgument(int argc, char **argv, struct Arguments *args)
{
    char *mc = calloc(100, sizeof(char));
    char *kc = calloc(100, sizeof(char));
    char *oc = calloc(100, sizeof(char));
    char *fc = calloc(100, sizeof(char));

    int e = 0, d = 0, m = 0, f = 0, o = 0, k = 0, g = 0, h = 0, narg = 1;
    char **ep = NULL, **dp = NULL, **mp = NULL, **fp = NULL, **op = NULL, **kp = NULL, **gp = NULL;

    tagType(argc, argv, &e, &d, &m, &f, &o, &k, &g, &h, &narg, &ep, &dp, &mp, &fp, &op, &kp, &gp);
    if (errorType(argc, argv, e, d, m, f, o, k, g, h, narg, ep, dp, mp, fp, op, kp, gp, &mc, &fc, &oc, &kc, args) == 0)
    {
        free(mc);
        free(kc);
        free(fc);
        free(oc);
        return 0;
    }

    /* kc's contents were already copied into args->forwardkey/reverseKey
     * by keyValidate(); the raw buffer itself is never needed again. */
    free(kc);

    /* Only the buffer for the input mode actually used (-m or -f) was
     * handed off to `args`; free whichever one was left untouched. */
    if (m == 0)
    {
        free(mc);
    }
    if (f == 0)
    {
        free(fc);
    }
    if (o == 0)
    {
        free(oc);
    }

    if (e == 1)
    {
        args->encrypt = true;
    }
    else if (d == 1)
    {
        args->decrypt = true;
    }
    if (g == 1)
    {
        keyGenerate(args);
        args->keyIsGenerated = true;
    }

    return 1;
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
                fclose(fp);
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

/*
 * Applies the forward or reverse substitution key to every alphabetic
 * character in args->inputMessage, preserving case and passing through
 * all non-alphabetic bytes unchanged.
 *
 * As in keyValidate(), every ctype.h call is given an `unsigned char`
 * to avoid undefined behavior on high-bit-set bytes when `char` is
 * signed.
 */
char *transformText(struct Arguments *args)
{
    size_t n = strlen(args->inputMessage);
    char *fm = calloc(n + 1, sizeof(char));
    if (args->encrypt)
    {
        for (size_t i = 0; i < n; i++)
        {
            unsigned char ch = (unsigned char)(args->inputMessage)[i];
            if (isalpha(ch))
            {
                int pos = tolower(ch) - 'a';
                fm[i] = (args->forwardkey)[pos];
                if (isupper(ch))
                {
                    fm[i] = (char)toupper((unsigned char)fm[i]);
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
            unsigned char ch = (unsigned char)(args->inputMessage)[i];
            if (isalpha(ch))
            {
                int pos = tolower(ch) - 'a';
                fm[i] = (args->reverseKey)[pos];
                if (isupper(ch))
                {
                    fm[i] = (char)toupper((unsigned char)fm[i]);
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

/*
 * Frees every heap buffer that may be hanging off `args` by the time
 * parseArgument() has returned successfully. Safe to call at any point
 * afterwards, and safe to call more than once: any field that was never
 * populated is NULL, and free(NULL) is a well-defined no-op.
 */
static void freeArgs(struct Arguments *args)
{
    free(args->inputMessage);
    free(args->outputMessage);
    free(args->inputFile);
    free(args->outputFile);
    args->inputMessage = NULL;
    args->outputMessage = NULL;
    args->inputFile = NULL;
    args->outputFile = NULL;
}

int main(int argc, char **argv)
{
    printf("CipherCLI: \n");
    args args = {0};
    int fa = parseArgument(argc, argv, &args);

    if (fa == 0)
    {
        /* parseArgument() already released everything it allocated. */
        return 0;
    }
    if (args.inputFromFile)
    {
        if (readFile(&args) == 0)
        {
            printError(14);
            freeArgs(&args);
            return 0;
        }
    }
    if (args.keyIsGenerated)
    {
        printf("Generated Key: %s\n", args.forwardkey);
    }

    transformText(&args);
    if (args.outputToFile)
    {
        if (writeFile(&args) == 0)
        {
            printError(13);
            freeArgs(&args);
            return 0;
        }
        printf("Message has been written to the specified output file.\n");
    }
    else
    {
        printf("Encrypted Text: %s\n", args.outputMessage);
    }

    freeArgs(&args);
    return 0;
}