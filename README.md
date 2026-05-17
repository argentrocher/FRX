# FRX
compilateur windows 64 bit uniquement, en cour de développement

asm_cpp64 est un compiler windows 64 base sur l'api pe_gen_window64.hpp fonctionnel, découvrer le et executer les test.asm !

Commandes de compilation :
<br><strong>asm_cpp64 <source.asm> <output.exe> [--see_all_exception] [--cmd/--gui] [--debug] [--no_test_code] [--dll]</strong>

Détail :
<br><strong>
source.asm = fichier de code asm<br>
output.exe = nom du fichier sur lequel le resultat de l'opération est fait<br>
 --see_all_exception = voir les logs de l'appi du compilateur<br>
 --cmd != --gui = permet d'avoir le cmd ou non (par défaut --gui)<br>
 --dll = permet de compiler en tant que ficher dll<br> ↪ (! le point d'entré correspond à BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason,LPVOID lpvReserved) → doit renvoyer <code>mov eax, 1</code> pour ok accès fonction)<br>
 --debug = voir les information de débuggage de lecture du fichier configuration<br>
 --no_test_code = désactive le débuggage des instruction (si on a déjà tester, permet d'accèlérer le constructeur, option déconseiller !)<br>
 </strong>

 Fonctionnement par section (écrire <code>section &lt;section></code>) :

 <strong>.data :</strong>
 Section qui contient les ressources du code avec les différents type de tampons mémoires suivant possibles :
 + <code>buffer &lt;name> &lt;int></code> avec &lt;name> le nom partagé pour accès entre les sections, <int> la taille du tampon en octet.
 + <code>ascii &lt;name> "&lt;string>"</code> avec &lt;string> le texte du tampon en ascii (terminer automatiquement par "\x00").
 + <code>utf16 &lt;name> "&lt;string>"</code> avec &lt;string> le texte du tampon en utf-16 (terminer automatiquement par "\x0000").
 + <code>little &lt;name> &lt;number/hex></code> avec &lt;number/hex> soit un nombre entier convertit soit un hexadécimal si commence par 0x et enregistré en little endian (terminer automatiquement par "\x00").
 + <code>big &lt;name> &lt;number/hex></code> avec &lt;number/hex> soit un nombre entier convertit soit un hexadécimal si commence par 0x et enregistré en big endian (terminer automatiquement par "\x00").

Pour accèder aux tampons dans le code, mettre le nom du tampon avec $ ou @ (voir .text).

<strong>.idata :</strong>
Section qui contient les adresses d'importation des dll :
+ <code>&lt;dllname> &lt;fonction> [...] &lt;fonction></code> avec &lt;dllname> le nom de la dll à charger et &lt;fonction> chaques fonctions chargés.

Pour accèder aux fonctions dans le code, mettre le nom de la fonction avec $ ou @ (voir .text).
