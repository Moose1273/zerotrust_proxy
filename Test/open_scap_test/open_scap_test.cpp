#include "open_scap_test.h"
#define XCCDF_FILE_NAME "content/ssg-rhel8-xccdf.xml"
using namespace std;
int main() {
    //Load the XCCDF document
    oscap_source* source = oscap_source_new_from_file(XCCDF_FILE_NAME);
    if (!source) {
        std::cerr << "Failed to load XCCDF document" << std::endl;
        return 1;
    }
    //cout<<oscap_source_get_schema_version(source)<<endl;
    //Load the benchmark
    xccdf_benchmark* benchmark = xccdf_benchmark_import_source(source);
    if (!benchmark) {
        std::cerr << "Failed to load benchmark" << std::endl;
        oscap_source_free(source);
        return 1;
    }
    //cout<<xccdf_benchmark_resolve(benchmark)<<endl;

    //Load the xccdf_profile
    xccdf_profile* x_profile = xccdf_profile_new();
    if (!x_profile) {
        std::cerr << "Failed to load x_profile" << std::endl;
        oscap_source_free(source);
        return 1;
    }
    //todo: there is a problem here
    //const char* msg = xccdf_profile_get_version(x_profile);
    // if(msg == nullptr){
    //     cout<<"failed"<<endl;
    //     return -1;
    // }
    //cout<<msg<<endl;

    //Load the xccdf_policy_model 
    xccdf_policy_model* policy_model = xccdf_policy_model_new(benchmark);
    if (!policy_model) {
        std::cerr << "Failed to load policy_model" << std::endl;
        oscap_source_free(source);
        return 1;
    }
    //Load the xccdf_policy 
    xccdf_policy*  x_policy = xccdf_policy_new(policy_model, x_profile);
    if (!x_policy) {
        std::cerr << "Failed to load x_policy" << std::endl;
        oscap_source_free(source);
        return 1;
    }
    //cout<<xccdf_policy_resolve(x_policy)<<endl;

    //Load the xccdf_result
    xccdf_result* result = xccdf_policy_evaluate(x_policy);
    if (!result) {
        std::cerr << "Failed to load result" << std::endl;
        oscap_source_free(source);
        return 1;
    }
    //cout<<xccdf_result_get_test_system(result)<<endl;
    //xccdf_result_rule_next

    // oscap_source* result_source = xccdf_result_export_source(result, "result.xml");
    // if (result_source == NULL) {
    //     std::cerr << "Error: Failed to export evaluation results to file " << std::endl;
    //     return -1;
    // }
    
    // 获取xccdf_rule_result对象列表
    xccdf_rule_result_iterator* rule_results_iter = xccdf_result_get_rule_results(result);
    while(xccdf_rule_result_iterator_has_more(rule_results_iter)){
        struct xccdf_rule_result *rule_result = xccdf_rule_result_iterator_next(rule_results_iter);
        float test_result_weight = xccdf_rule_result_get_weight(rule_result);
        xccdf_level_t test_result_severity = xccdf_rule_result_get_severity(rule_result);
        xccdf_test_result_type_t test_result_type = xccdf_rule_result_get_result(rule_result);
        cout<<"test_result is: "<< " test_result: " << test_result_weight
        << " test_result_severity: " << test_result_severity
        << " test_result_type: " << test_result_type
        <<endl;
    }
    xccdf_rule_result_iterator_free(rule_results_iter);
    
    cout<<"finished "<<endl;
    // Free resources
    oscap_source_free(source);
    xccdf_policy_free(x_policy);
    xccdf_benchmark_free(benchmark);
    //oscap_source_free(result_source);
    return 0;
}
