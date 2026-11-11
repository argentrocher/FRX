//by argentropcher

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

#pragma once

int eval_is_not_number = 0;
int num_scientific_mode = 0;
int num_type_comma = 0;

int is_space(char c){ return c==' ' || c=='\t' || c=='\n' || c=='\r'; }

// fonction remplacer les virgules en points
void replace_comma_with_dot(char *str) {
    while (*str) {
        if (*str == ',') {
            *str = '.';
        }
        str++;
    }
}

//fonction de parsing des nombre général
void regex_format_double(double value, char *out, size_t size) {
    // Conversion brute avec 16 chiffres significatifs
    if (num_scientific_mode) {
        snprintf(out, size, "%.15g", value);
    } else {
        // %.16f affiche assez de décimales pour un double sans passer en e+
        //snprintf(out, size, "%.15f", value);

        // nombre de chiffres avant la virgule
        double abs_val = (value < 0) ? -value : value;
        int int_digits = 1;
        if (abs_val >= 1.0) {
            int_digits = (int)floor(log10(abs_val)) + 1;
        }

        // nombre max de chiffres significatifs pour un double ~15
        int decimals = 15 - int_digits;
        if (decimals < 0) decimals = 0;        // pas de décimales si nombre très grand
        if (decimals > 14) decimals = 14;      // sécurité

        // conversion en chaîne
        char fmt[16];
        snprintf(fmt, sizeof(fmt), "%%.%df", decimals); // format dynamique
        snprintf(out, size, fmt, value);
    }

    out[size - 1] = '\0';

    replace_comma_with_dot(out);
    // Vérifie si un point existe déjà
    char *dot = strchr(out, '.');
    if (!dot) {
        // Pas de décimale -> ajouter ".00"
        //strncat(out, ".00", size - strlen(out) - 1);
        size_t len = strlen(out);
        if (len + 3 < size)
            memcpy(out + len, ".00", 4);
    } else {
        int decimals = strlen(dot + 1);
        size_t len = strlen(out);

        // Si moins de 2 décimales -> compléter avec des 0
        while (decimals < 2 && len < size - 1) {
            //strncat(out, "0", size - strlen(out) - 1);
            out[len++] = '0';
            out[len] = '\0';
            decimals++;
        }

        // Si plus de 2 décimales -> enlever les 0 inutiles à droite
        char *end = out + len - 1;
        while (decimals > 2 && *end == '0') {
            *end = '\0';
            end--;
            decimals--;
        }
    }
    //remplacer . par virgule si voulu par l'utilisateur
    if (num_type_comma){
        char *str = out;
        while (*str) {
        if (*str == '.') {
            *str = ',';
        }
        str++;
        }
    }
    out[size - 1] = '\0';
}

double eval_expr(const char *expr, int *index);

// Fonction pour lire les nombres dans l'expression
double parse_number(const char *expr, int *index) {
    double num = 0;
    int sign = 1;

    // Vérifier s'il y a un signe "-" ou "+"
    if (expr[*index] == '-') {
        sign = -1;
        (*index)++;
    } else if (expr[*index] == '+') {
        (*index)++;
    }

    // Lire les chiffres du nombre
    while (isdigit(expr[*index])) {
        num = num * 10 + (expr[*index] - '0');
        (*index)++;
    }

    // Lire la partie décimale si présente
    if (expr[*index] == '.' || expr[*index] == ',') {
        (*index)++;
        double fraction = 1;
        while (isdigit(expr[*index])) {
            fraction *= 0.1;
            num += (expr[*index] - '0') * fraction;
            (*index)++;
        }
    }

    return num * sign;  // Retourner le nombre avec le signe correct
}

// Nombre ou expression entre parenthèses
double parse_primary(const char *expr, int *index) {
    double value = 0;

    // Lire un nombre ou une parenthèse
    if (expr[*index] == '(') {
        (*index)++; // Passer la parenthèse ouvrante
        value = eval_expr(expr, index); // Évaluer l'expression à l'intérieur des parenthèses
        if (expr[*index] == ')') {
            (*index)++; // Passer la parenthèse fermante
        }
    } else {
        value = parse_number(expr, index); // Si ce n'est pas une parenthèse, on lit un nombre
    }

    return value;
}

// NON logique
double parse_not(const char *expr, int *index) {
    if (expr[*index] == '!') {
        (*index)++;

        double value = parse_not(expr, index);

        return (value == 0.0) ? 1.0 : 0.0;
    }

    return parse_primary(expr, index);
}

// Puissance
double parse_power(const char *expr, int *index) {
    double value = parse_not(expr, index);

    //les puissances comme pow(;)
    while (expr[*index] == '^') {
        (*index)++;
        double exponent = parse_power(expr, index);
        value = pow(value, exponent);
    }
    return value;
}

double parse_unary(const char *expr, int *index) {
    int sign = 1;
    int the_index = *index;

    // Parcourir tous les signes consécutifs
    while (expr[*index] == '+' || expr[*index] == '-') {
        if (expr[*index] == '-') sign = -sign;
        (*index)++;
    }
    if (expr[*index] == '(') {
        return sign * parse_power(expr, index);
    } else if (the_index != *index) {
        (*index)--;
        if (sign == 1 && expr[*index] != '\0') {
            ((char*)expr)[*index] = '+';
        } else if (sign == -1 && expr[*index] != '\0') {
            ((char*)expr)[*index] = '-';
        }
    }
    return parse_power(expr, index);
}

// Fonction pour évaluer les termes séparés par * ou /
double parse_term(const char *expr, int *index) {
    double value = parse_unary(expr, index);
    int state = 0;

    // Gérer les multiplicateurs et diviseurs en suivant les priorités
    while (expr[*index] == '*' || expr[*index] == '/' || expr[*index] == '%' || expr[*index] == '#') {
        char op = expr[*index];
        (*index)++;

        // Si l'opérateur suivant est *, diviser ou multiplier le terme précédent
        double next_value = 0;
        if (expr[*index] == '(') {
            (*index)++;  // Passer la parenthèse ouvrante
            next_value = eval_expr(expr, index);  // Récursivement évaluer l'expression dans les parenthèses
            if (expr[*index] == ')') {
                (*index)++;  // Passer la parenthèse fermante
            }
        } else {
            next_value = parse_number(expr, index);  // Lire un nombre normal
        }

        if (op == '*') {
            value *= next_value;
        } else if (op == '/') {
            if (next_value == 0) {
#ifdef __cplusplus
                throw "Error: division by zero.";
#else
                puts("Error: division by zero.");
#endif
                state = 1;
                // Sortir en cas de division par zéro
            } else {
                value /= next_value;
            }
        } else if (op == '#') {
            if (next_value == 0) {
#ifdef __cplusplus
                throw "Error: integer division by zero.";
#else
                puts("Error: integer division by zero.");
#endif
                state = 1;
                // Sortir en cas de division par zéro
            } else {
                // Division entière (tronquée)
                long long a = (long long)value;
                long long b = (long long)next_value;
                value = (double)(a / b);
            }
        } else if (op == '%') {
            long long a = (long long)value;
            long long b = (long long)next_value;
            if (b == 0) {
#ifdef __cplusplus
                throw "Error: modulo by zero.";
#else
                puts("Error: modulo by zero.");
#endif
                state = 1;
                // Sortir en cas de division par zéro
            } else {
                value = a % b;
            }
        }
    }

    if (state == 1) {
        value = 0.00;
    }

    return value;
}

// Fonction principale pour évaluer une expression
double parse_add(const char *expr, int *index) {
    double value = parse_term(expr, index); // Évaluer le premier terme (gère la multiplication et la division) (+modulo)

    while (expr[*index] != '\0') {
        if (expr[*index] == '+' || expr[*index] == '-') {
            char op = expr[*index];
            (*index)++; // Passer à l'opérateur suivant

            double next_value = parse_term(expr, index); // Récupérer la valeur suivante

            // Appliquer l'opérateur à la valeur
            if (op == '+') {
                value += next_value;
            } else if (op == '-') {
                value -= next_value;
            }
        }
        else {
            break; // Sortir de la boucle si un caractère invalide est trouvé
        }
    }

    return value;
}

// Fonction pour gérer l'opérateur binaire &
double parse_and(const char *expr, int *index) {
    double value = parse_add(expr, index);

    while (expr[*index] == '&') {
        (*index)++;

        double next_value = parse_add(expr, index);

        long long a = (long long)value;
        long long b = (long long)next_value;

        value = (double)(a & b);
    }

    return value;
}


// Fonction pour gérer l'opérateur binaire |
double parse_or(const char *expr, int *index) {
    double value = parse_and(expr, index);

    while (expr[*index] == '|') {
        (*index)++;

        double next_value = parse_and(expr, index);

        long long a = (long long)value;
        long long b = (long long)next_value;

        value = (double)(a | b);
    }

    return value;
}

double eval_expr(const char *expr, int *index) {
    return parse_or(expr, index);
}

// Fonction pour ajouter une multiplication implicite dans l'expression
void handle_implicit_multiplication(char *expr) {
    int len = strlen(expr);

    // Parcours de l'expression pour vérifier si un nombre est suivi immédiatement d'une parenthèse ouvrante
    for (int i = 0; i < len - 1; i++) {
        if (((isdigit(expr[i]) || expr[i] == ')') && expr[i + 1] == '(') || (expr[i] == ')' && isdigit(expr[i+1]))) {
            // Insérer un '*' entre le nombre et la parenthèse
            memmove(&expr[i + 2], &expr[i + 1], len - i);  // Décaler les caractères
            expr[i + 1] = '*';  // Ajouter '*' entre le nombre et la parenthèse
            len++;  // Mettre à jour la longueur de l'expression après insertion
            i++;  // Passer à l'indice suivant pour éviter de traiter plusieurs fois la même paire
        }
    }
}

// Fonction principale pour évaluer une expression à partir d'une chaîne de caractères
double eval(char *expr) {
    // Remplacer "infini" / "endless" par 10^308
    const char *replacement = "(10^308)";
    const char *words[] = {"infini", "endless"};
    for (int w = 0; w < 2; w++) {
        char *p;
        size_t word_len = strlen(words[w]);
        size_t rep_len  = strlen(replacement);

        while ((p = strstr(expr, words[w])) != NULL) {
            // Décaler le reste de la chaîne pour faire de la place ou compresser
            memmove(p + rep_len, p + word_len, strlen(p + word_len) + 1);
            // Copier le remplacement
            memcpy(p, replacement, rep_len);
        }
    }
    handle_implicit_multiplication(expr);  // Appeler la fonction pour ajouter les multiplications implicites
    int index = 0;
    double result = eval_expr(expr, &index);  // Appeler eval_expr pour évaluer l'expression modifiée

    //signal que val ne contient pas qu'un nombre
    while (is_space(expr[index])) index++;
    if (expr[index] != '\0')
        eval_is_not_number = 1;

    return result;
}

char *string_convert(const char *input, size_t len_optional, size_t *capacity, int without_decimal) {
    const char *ptr = input;

    size_t result_capacity = 2048;
    size_t temp_capacity = 2048;

    if (len_optional) {
        //marge car ajout généralement faible donc évite realloc
        result_capacity = len_optional+100;
        temp_capacity = len_optional+100;
    }

    size_t result_len = 0;

    char *result = (char*)malloc(result_capacity);
    if (!result)
        return NULL;

    result[0] = '\0';

    size_t temp_len = 0;

    char *temp = (char*)malloc(temp_capacity);
    if (!temp) {
        free(result);
        return NULL;
    }

    int in_quotes = 0;
    int paren_level = 0;

    size_t slash_count = 0;

    while (*ptr) {
        int escaped_quote = 0;
        if (*ptr == '"') {
            escaped_quote = (slash_count % 2) != 0;
        }

        if (*ptr == '(' && !in_quotes) {
            paren_level++;
        }
        else if (*ptr == ')' && !in_quotes) {
            if (paren_level > 0)
                paren_level--;
        }
        if (*ptr == '"' && paren_level == 0 && !escaped_quote) {
            temp[temp_len] = '\0';
            if (in_quotes) {
                // Copier directement dans result
                if (result_len + temp_len + 1 > result_capacity) {
                    while (result_len + temp_len + 1 > result_capacity)
                        result_capacity *= 2;
                    char *new_result = (char*)realloc(result, result_capacity);
                    if (!new_result) {
                        free(temp);
                        free(result);
                        return NULL;
                    }
                    result = new_result;
                }

                memcpy(result + result_len, temp, temp_len);
                result_len += temp_len;
                result[result_len] = '\0';

            } else if (temp_len > 0) {
                char formatted[512];
                char *temp_ptr = temp;
                while (*temp_ptr && isspace((unsigned char)*temp_ptr)) temp_ptr++;
                double resu = eval(temp_ptr);
                if (without_decimal) {
                    snprintf(formatted, sizeof(formatted), "%.0f", resu);
                    formatted[sizeof(formatted)-1] = '\0';
                } else {
                    regex_format_double(resu, formatted, sizeof(formatted));
                }

                size_t formatted_len = strlen(formatted);

                if (result_len + formatted_len + 1 > result_capacity) {
                    while (result_len + formatted_len + 1 > result_capacity)
                        result_capacity *= 2;

                    char *new_result = (char*)realloc(result, result_capacity);
                    if (!new_result) {
                        free(temp);
                        free(result);
                        return NULL;
                    }
                    result = new_result;
                }

                memcpy(result + result_len, formatted, formatted_len);
                result_len += formatted_len;
                result[result_len] = '\0';
            }
            temp_len = 0;
            in_quotes = !in_quotes;

        } else {
            if (temp_len + 1 >= temp_capacity) {
                temp_capacity *= 2;
                char *new_temp = (char*)realloc(temp, temp_capacity);
                if (!new_temp) {
                    free(temp);
                    free(result);
                    return NULL;
                }
                temp = new_temp;
            }
            temp[temp_len++] = *ptr;
        }

        // Compte antislashs
        if (*ptr == '\\')
            slash_count++;
        else
            slash_count = 0;

        ptr++;
    }

    if (!in_quotes && temp_len > 0) {
        temp[temp_len] = '\0';

        char formatted[512];
        char *temp_ptr = temp;
        while (*temp_ptr && isspace((unsigned char)*temp_ptr)) temp_ptr++;
        double resu = eval(temp_ptr);
        if (without_decimal) {
            snprintf(formatted, sizeof(formatted), "%.0f", resu);
            formatted[sizeof(formatted)-1] = '\0';
        } else {
            regex_format_double(resu, formatted, sizeof(formatted));
        }

        size_t formatted_len = strlen(formatted);
        if (result_len + formatted_len + 1 > result_capacity) {
            while (result_len + formatted_len + 1 > result_capacity)
                result_capacity *= 2;

            char *new_result = (char*)realloc(result, result_capacity);
            if (!new_result) {
                free(temp);
                free(result);
                return NULL;
            }
            result = new_result;
        }
        memcpy(result + result_len, formatted, formatted_len);
        result_len += formatted_len;
        result[result_len] = '\0';
    }
    free(temp);
    if (capacity) {
        *capacity = result_capacity;
    }
    return result;
}
