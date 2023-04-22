#include "fuzzer/FuzzedDataProvider.h"
#include "libInterpolate/Interpolate.hpp"


constexpr const std::size_t min_size = sizeof(float) * 6;

std::vector<double> make_random_vector(FuzzedDataProvider& fdp) noexcept {
    auto sz = fdp.ConsumeIntegralInRange<std::size_t>(1, 1000);
    std::vector<double> vec;
    vec.reserve(sz);
    for (std::size_t i = 0; i < sz; ++i) {
        vec.push_back(fdp.ConsumeFloatingPoint<double>());
    }
    return vec;
}

extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    if (size < min_size) {
        return -1;
    }

    auto x = make_random_vector(fdp);
    auto y = make_random_vector(fdp);
    _1D::CubicSplineInterpolator<double> interp{x,y};
    interp(fdp.ConsumeFloatingPoint<double>());

    return 0;
}
