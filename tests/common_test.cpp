#include <fstream>

constexpr char test_file_content[1880] = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. \
Etiam egestas nulla lorem, ut eleifend nulla feugiat a. Pellentesque eu tellus fringilla, \
congue massa eu, convallis nisl. Sed accumsan ligula elit, vel suscipit dui fringilla eget. \
Morbi a nisl id ante blandit rutrum sed vel quam. Donec erat quam, cursus a imperdiet nec, \
interdum id nulla. Ut consectetur semper diam, malesuada rutrum libero tempor vitae. Pellentesque \
sodales, lectus vitae posuere fermentum, lorem lectus accumsan augue, a mattis magna libero eget ex. \
Integer aliquet justo libero, fermentum imperdiet enim ornare at. Donec consequat justo risus, a \
tincidunt enim tincidunt vel. Proin at turpis feugiat, rhoncus ante ac, lacinia nisi. \
Donec efficitur, nunc vitae posuere tincidunt, odio nunc lacinia nulla, quis dictum \
ipsum enim eget arcu. Quisque sed efficitur tellus, in tincidunt tortor. Sed ut rhoncus sem, ac tempor \
orci. Nunc in libero faucibus, vestibulum metus non, fringilla ligula. Praesent lobortis finibus libero \
ac rhoncus.\n\
\n\
Nam nulla erat, aliquet vitae leo sed, ullamcorper egestas felis.Donec ultricies hendrerit ante vel \
imperdiet.Pellentesque sollicitudin vel nisl at vestibulum.Suspendisse mi neque, congue sed ullamcorper \
gravida, rutrum nec ipsum.Sed augue ipsum, vehicula et fermentum ut, dictum ac sapien.Ut est lorem, \
finibus quis pretium id, bibendum tincidunt ante.Nulla interdum nibh ut tellus tempus, ut lobortis \
eros dignissim.Suspendisse potenti.Suspendisse velit felis, malesuada quis felis eu, sagittis varius \
ligula.Nulla ligula mauris, pellentesque eu nisi et, posuere porttitor tellus.Quisque vulputate dictum \
felis scelerisque blandit.Mauris in aliquam massa.Sed ultricies sit amet ligula non facilisis.Morbi massa \
erat, ultricies sit amet laoreet a, eleifend ac sem.Maecenas vestibulum iaculis tellus, nec tempus dui \
mattis sed.Sed elementum sollicitudin sagittis.";

void generate_test_file() {
	std::ifstream test("testfile.txt");
	if (!test.good()) {
		std::ofstream testfile("testfile.txt");
		if (testfile.is_open()) {
			testfile.write(test_file_content, sizeof(test_file_content));
		}
		testfile.close();
	}
	test.close();
}