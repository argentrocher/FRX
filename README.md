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

Fonctionnement avant les sections :
+ <code>ASM64CPP</code> évite un avertissement pour risque d'incompatibilité à écrire en premier sur la première ligne du fichier. 
+ <code>global &lt;fonctionname>:</code> avec &lt;fonctionname> qui définit la fonction point d'entré du code (démarage du code en exécutable ou équivalent à DllMain en dll), par défaut, le point d'entré est <code>main</code>.
+ <code>include default:</code> importe la liste des fonctions par défaut (visible sur default_asm_func_in_static.c même si le code a évolué avec @ au lieu de $ pour la compatibilité en dll, voir .text).
+ <code>include "&lt;file>"</code> importe un autre fichier sous même format et le mélange (! à l'unicitée des adresses !). 

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

<strong>.edata :</strong>
Section qui contient les adresses des fonctions/tampons a exporter (principalement pour fichier .dll mais fonctionne parfois avec .exe) :
+ <code>local &lt;exportname> [&lt;filename>]</code> avec &lt;exportname> le nom exporté donnant accès à un autre fichier (.exe ou .dll) à la fonction/tampon et [&lt;filename>] optionnel si le nom dans le code asm n'est pas celui que l'on veut exporter.
+ <code>extern &lt;exportname> &lt;importdllfonction></code> avec &lt;exportname> le nom exporté donnant accès à un autre fichier (.exe ou .dll) à la fonction/tampon fournit par une autre dll et sa fonction/tampon de &lt;importdllfonction> (ex: <code>extern print msvcrt.printf</code> lorsque l'on importe cette dll, si on appel la fonction print, cela appelera en réalité msvcrt et la fonction printf).

<strong>.rsrc :</strong>
Section qui contient l'icone, les boîtes de dialogue, le manifest et la version de l'application :
+ <code>icon "&lt;iconpath>"</code> avec &lt;iconpath> le chemin de l'image .ico a définir comme icone ( ! a l'emplacement de l'exécution de la commande).
+ <code>version_simple "&lt;version>" "&lt;nameapp>" "&lt;copyright>"</code> avec &lt;version> la version du fichier (généralement sous cette forme 0.0.0.0), &lt;nameapp> est le nom d'origine de vôtre application, &lt;copyright> le texte que vous voulez mettre en copyright.
+ <code>version_full "&ltfileVersion>" "&ltproductVersion>" "&ltcompanyName>" "&ltfileDescription>" "&ltproductName>" "&ltoriginalFilename>" "&ltcopyright>"</code> permet d'avoir accès a tout les champs.
+ <code>manifest_simple "&lt;nameapp>" "&lt;version>" &lt;dpiAware> &lt;perMonitorV2> &lt;requireAdmin> &lt;commonV6></code> avec &lt;nameapp> nom de l'application, &lt;version> version de l'application (sous même format 0.0.0.0), puis des bool <code>true</code> ou <code>false</code> : &lt;dpiAware>  &lt;perMonitorV2> &lt;requireAdmin> &lt;commonV6>.
+ <code>manifest_xml "&lt;contain>"</code> avec &lt;contain> le contenu du fichier xml complet.
+ <code>dialog</code> et <code>control</code> (les control doivent suivrent dialog même si l'id les lies ensemble), voir exemple test3.asm ou code C++.

<strong>.text :</strong>
Section qui contient tout le code machine asembleur x86_64 (fait par keystone.dll) :
<ul>
<li>Une fonction commence par proc &lt;name> et finit par end &lt;name>.</li>
<li>Pour joindre une fonction ou un tampon mémoire, 2 méthodes différentes sont proposé :</li>
<ul>
 <li><code>$&lt;name></code> avec &lt;name> le nom a joindre. $ donne l'adresse en adresse absolu. Cela est plus rapide que l'adresse relative en temps de calcul à la compilation mais ne fonctionne que lorsque l'image est chargé à ça base donc seulement en .exe </li>
 <li><code>@&lt;name></code> avec &lt;name> le nom a joindre. @ donne l'adresse relative, il faut utiliser <code>[rip+@name]</code> avec <code>lea</code> ou <code>mov</code>. Lors de sont utilisation dans des fonctions, l'utilisation de <strong>0xFFFFFFFF</strong> ou <strong>0xFFFFFFFFFFFFFFFF</strong> est interdite car le calculateur utilise ces valeurs comme repère pour calculer l'adresse relative.</li>
</ul>
</ul>

<strong>Merci d'avoir choisi FRX et asm_cpp64 de argentropcher !<br>
A vous de créer !</strong>




