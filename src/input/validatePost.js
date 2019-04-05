const Ajv = require('ajv');
const AjvErrors = require('ajv-errors');

const ajv = new Ajv({allErrors: true, jsonPointers: true});
AjvErrors(ajv, {singleError: true});
const schema = {
    title: 'PostSubmission',
    properties: {
        post: {type: 'string', minLength: 1, maxLength: 140}
    },
    additionalProperties: false,
    required: ['post'],
    errorMessage: 'Please use between 1 and 140 characters'
};
const validatePost = ajv.compile(schema);

module.exports = validatePost;