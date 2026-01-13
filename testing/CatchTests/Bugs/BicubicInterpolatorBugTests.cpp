#include <catch2/catch_approx.hpp>
#include <catch2/catch_test_macros.hpp>
#include <libInterpolate/Interpolators/_2D/BicubicInterpolator.hpp>
#include <vector>

TEST_CASE("BicubicInterpolator bug fix test: f(x,y) = -x*y + 2.5*x + y - 3",
          "[bugs]") {
    auto f = [](double x, double y) { return -x * y + 2.5 * x + y - 3; };

    std::vector<double> x_coords = {0.0, 1.0, 2.0};
    std::vector<double> y_coords = {0.0, 1.0, 2.0};
    std::vector<double> z_values(x_coords.size() * y_coords.size());

    // Populate z_values
    for (size_t i = 0; i < x_coords.size(); ++i) {
        for (size_t j = 0; j < y_coords.size(); ++j) {
            z_values[i * y_coords.size() + j] = f(x_coords[i], y_coords[j]);
        }
    }

    _2D::BicubicInterpolator<double> interp;
    interp.setData(x_coords, y_coords, z_values);

    // Test points
    SECTION("Interpolate at known data points") {
        REQUIRE(interp(0.0, 0.0) == Catch::Approx(f(0.0, 0.0)));
        REQUIRE(interp(1.0, 1.0) == Catch::Approx(f(1.0, 1.0)));
        REQUIRE(interp(2.0, 2.0) == Catch::Approx(f(2.0, 2.0)));
    }

    SECTION("Interpolate at intermediate points") {
        REQUIRE(interp(0.5, 0.5) == Catch::Approx(f(0.5, 0.5)));
        REQUIRE(interp(1.5, 0.5) == Catch::Approx(f(1.5, 0.5)));
        REQUIRE(interp(0.5, 1.5) == Catch::Approx(f(0.5, 1.5)));
        REQUIRE(interp(1.5, 1.5) == Catch::Approx(f(1.5, 1.5)));
    }
}
